from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import logging
import mmap
import os
import re
import select
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
import zlib
from io import BytesIO
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence


_BUNDLED_PACKAGES = Path(__file__).resolve().parent / "python-packages"
if _BUNDLED_PACKAGES.is_dir():
    sys.path.insert(0, str(_BUNDLED_PACKAGES))
_PY39_PACKAGES = Path(__file__).resolve().parent / "python-packages-py39"
if sys.version_info[:2] == (3, 9) and _PY39_PACKAGES.is_dir():
    # Pillow contiene extensiones nativas ligadas a la versión del intérprete.
    # La capa 3.9 debe preceder al conjunto moderno usado por Apple Silicon.
    sys.path.insert(0, str(_PY39_PACKAGES))

try:
    from PIL import Image, ImageOps, UnidentifiedImageError
except ImportError:
    Image = None  # type: ignore[assignment]
    ImageOps = None  # type: ignore[assignment]
    UnidentifiedImageError = OSError  # type: ignore[assignment,misc]


LOGGER = logging.getLogger("forensic_mobile_lab")


class AcquisitionError(RuntimeError):
    pass


class HardwareTimeoutError(AcquisitionError):
    pass


class CRCMismatchError(AcquisitionError):
    pass


class DevicePermissionError(AcquisitionError):
    pass


class DeviceLockedError(AcquisitionError):
    pass


class CorruptDataError(AcquisitionError):
    pass


class ProtocolError(AcquisitionError):
    pass


class ADBNotFoundError(AcquisitionError):
    pass


def _verify_hash_chain(path: Path, collection_key: str, scheme: str) -> dict[str, Any]:
    """Valida el encadenamiento semántico aun si se reconstruyó el manifiesto."""
    if not path.is_file():
        return {"path": path.name, "present": False, "valid": True, "events": 0}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        events = payload.get(collection_key, [])
        if not isinstance(events, list):
            raise ValueError("la colección de eventos no es una lista")
        previous = "0" * 64
        for index, item in enumerate(events):
            if not isinstance(item, dict) or item.get("previous_hash") != previous:
                raise ValueError(f"enlace inválido en evento {index}")
            if scheme == "custody":
                source = {key: value for key, value in item.items()
                          if key not in {"previous_hash", "event_hash"}}
                canonical = json.dumps(source, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest()
            elif scheme == "annotation":
                canonical = "|".join(str(item.get(key, "")) for key in
                                     ("timestamp_utc", "evidence_sha256", "path", "tag", "note"))
                expected = hashlib.sha256(f"{previous}|{canonical}".encode("utf-8")).hexdigest()
            else:
                canonical = item.get("canonical")
                if not isinstance(canonical, str):
                    raise ValueError(f"payload canónico ausente en evento {index}")
                expected = hashlib.sha256(f"{previous}|{canonical}".encode("utf-8")).hexdigest()
            if item.get("event_hash") != expected:
                raise ValueError(f"hash inválido en evento {index}")
            previous = expected
        return {"path": path.name, "present": True, "valid": True,
                "events": len(events), "head": previous}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return {"path": path.name, "present": True, "valid": False,
                "events": 0, "error": str(error)}


class DeviceState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    AUTHORIZED = "authorized"
    LOCKED = "locked"
    READY = "ready"
    ERROR = "error"


class ArtifactType(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    CALL = "call"
    CONTACT = "contact"
    GENERIC = "generic"


@dataclass(frozen=True)
class DeviceIdentity:
    serial: str
    manufacturer: str
    model: str
    platform: str
    os_version: str
    transport: str


@dataclass(frozen=True)
class FileManifestEntry:
    logical_path: str
    evidence_path: str
    size: int
    sha256: str
    crc32: str
    acquired_at: str
    thumbnail_path: str | None = None
    is_recovered: bool = False
    captured_at: str | None = None
    exif_metadata: Mapping[str, Any] = field(default_factory=dict)
    case_relative_path: str | None = None
    thumbnail_relative_path: str | None = None


@dataclass(frozen=True)
class ParsedArtifact:
    artifact_type: ArtifactType
    source_database: str
    source_table: str
    record: Mapping[str, Any]


@dataclass
class AcquisitionResult:
    acquisition_id: str
    device: DeviceIdentity
    started_at: str
    completed_at: str | None = None
    manifest: list[FileManifestEntry] = field(default_factory=list)
    artifacts: list[ParsedArtifact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class MobileTransport(ABC):
    @abstractmethod
    def connect(self, timeout_seconds: float) -> None: ...

    @abstractmethod
    def exchange(self, request: bytes, timeout_seconds: float) -> bytes: ...

    @abstractmethod
    def identity(self) -> DeviceIdentity: ...

    @abstractmethod
    def is_locked(self) -> bool: ...

    @abstractmethod
    def iter_files(self, roots: Sequence[str]) -> Iterator[str]: ...

    @abstractmethod
    def read_file_chunks(
        self, logical_path: str, chunk_size: int
    ) -> Iterator[tuple[bytes, int]]: ...

    @abstractmethod
    def disconnect(self) -> None: ...


class RealADBTransport(MobileTransport):
    """Transporte ADB para equipos previamente autorizados por el propietario.

    Solo lee rutas accesibles al usuario Android ``shell``. No intenta root,
    escalada de privilegios, desbloqueo ni acceso a sandboxes de aplicaciones.
    """

    _COMMON_ADB_PATHS: Final[tuple[str, ...]] = (
        "/opt/homebrew/bin/adb",
        "/usr/local/bin/adb",
        "/Applications/Android Studio.app/Contents/sdk/platform-tools/adb",
    )
    _FORENSIC_SUFFIXES: Final[frozenset[str]] = frozenset(
        {
            ".db",
            ".sqlite",
            ".sqlite3",
            ".json",
            ".csv",
            ".crypt12",
            ".crypt14",
            ".crypt15",
            ".jpg",
            ".jpeg",
            ".png",
            ".heic",
            ".heif",
            ".webp",
            ".gif",
            ".dng",
            ".mp4",
            ".mov",
            ".3gp",
            ".m4a",
            ".aac",
            ".ogg",
            ".opus",
            ".deleted",
        }
    )
    _WHATSAPP_DATABASE_ROOTS: Final[tuple[str, ...]] = (
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/WhatsApp/Databases",
        "/storage/emulated/0/WhatsApp/Databases",
        "/data/data/com.whatsapp/databases",
        "/data/user/0/com.whatsapp/databases",
    )
    _PUBLIC_STORAGE_ROOTS: Final[tuple[str, ...]] = (
        "/sdcard",
        "/storage/emulated/0",
    )

    def __init__(self, serial: str | None = None, adb_path: str | None = None) -> None:
        self._serial = serial
        self._adb_path = self._locate_adb(adb_path)
        self._connected = False
        self._active_streams: set[subprocess.Popen[bytes]] = set()

    def connect(self, timeout_seconds: float) -> None:
        code, stdout, stderr = self._run_adb(["devices", "-l"], timeout_seconds, use_serial=False)
        if code != 0:
            raise AcquisitionError(f"ADB no pudo enumerar dispositivos: {stderr.strip()}")
        devices = self._parse_devices(stdout)
        if self._serial is None:
            ready = [serial for serial, state in devices if state == "device"]
            if len(ready) == 1:
                self._serial = ready[0]
            elif not ready:
                states = ", ".join(f"{serial}={state}" for serial, state in devices)
                detail = states or "ningún dispositivo detectado"
                raise DevicePermissionError(
                    "No hay un Android ADB autorizado. Desbloquea el teléfono, "
                    f"acepta la huella RSA y vuelve a intentar ({detail})."
                )
            else:
                raise ProtocolError(
                    "Hay varios dispositivos ADB; selecciona uno mediante --serial: "
                    + ", ".join(ready)
                )
        state = dict(devices).get(self._serial)
        if state == "unauthorized":
            raise DevicePermissionError("El dispositivo no ha autorizado esta Mac")
        if state == "offline":
            raise ProtocolError("El dispositivo ADB está offline")
        if state != "device":
            raise ProtocolError(f"Serie ADB no disponible: {self._serial}")
        code, stdout, stderr = self._run_adb(["get-state"], timeout_seconds)
        if code != 0 or stdout.strip() != "device":
            raise ProtocolError(f"ADB get-state falló: {stderr.strip()}")
        self._connected = True

    def exchange(self, request: bytes, timeout_seconds: float) -> bytes:
        self._ensure_connected()
        prefix = b"FORENSIC_HELLO:"
        if not request.startswith(prefix) or len(request[len(prefix):]) != 16:
            raise ProtocolError("Solicitud de handshake inválida")
        code, stdout, stderr = self._run_adb(
            ["shell", "id"], timeout_seconds
        )
        if code != 0 or "uid=2000" not in stdout:
            raise DevicePermissionError(
                f"No se obtuvo una sesión ADB shell autorizada: {stderr.strip()}"
            )
        nonce = request[len(prefix):]
        return b"FORENSIC_ACK:" + hashlib.sha256(nonce).digest()

    def identity(self) -> DeviceIdentity:
        self._ensure_connected()
        properties = {
            "manufacturer": self._getprop("ro.product.manufacturer"),
            "model": self._getprop("ro.product.model"),
            "platform": self._getprop("ro.build.version.release_or_codename"),
            "version": self._getprop("ro.build.version.release"),
        }
        return DeviceIdentity(
            serial=self._serial or "unknown",
            manufacturer=properties["manufacturer"] or "Android",
            model=properties["model"] or "Dispositivo ADB",
            platform=f"Android {properties['platform']}".strip(),
            os_version=properties["version"] or "unknown",
            transport="ADB USB autorizado",
        )

    def diagnostics(self) -> Mapping[str, Any]:
        """Obtiene telemetría de solo lectura para el preflight de adquisición."""
        self._ensure_connected()
        identity = self.identity()
        battery_code, battery_text, _ = self._run_adb(
            ["shell", "dumpsys", "battery"], 10.0
        )
        battery: dict[str, str] = {}
        if battery_code == 0:
            for line in battery_text.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    battery[key.strip()] = value.strip()
        storage_code, storage_text, _ = self._run_adb(
            ["shell", "df", "-k", "/sdcard"], 10.0
        )
        storage = "unknown"
        storage_total_kb = "unknown"
        storage_available_kb = "unknown"
        if storage_code == 0:
            rows = [row.split() for row in storage_text.splitlines() if row.strip()]
            if len(rows) >= 2 and len(rows[-1]) >= 5:
                storage = rows[-1][4]
                storage_total_kb = rows[-1][1]
                storage_available_kb = rows[-1][3]
        usb_config = self._getprop("sys.usb.config")
        patch_level = self._getprop("ro.build.version.security_patch")
        date_code, device_time, _ = self._run_adb(
            ["shell", "date", "+%Y-%m-%dT%H:%M:%S%z"], 10.0
        )
        timezone_name = self._getprop("persist.sys.timezone")
        return {
            "authorized": True,
            "locked": self.is_locked(),
            "identity": asdict(identity),
            "security_patch": patch_level or "unknown",
            "battery_level": battery.get("level", "unknown"),
            "battery_status": battery.get("status", "unknown"),
            "storage_used": storage,
            "storage_total_kb": storage_total_kb,
            "storage_available_kb": storage_available_kb,
            "usb_configuration": usb_config or "unknown",
            "device_time": device_time.strip() if date_code == 0 else "unknown",
            "device_timezone": timezone_name or "unknown",
            "mac_time_utc": _utc_now(),
            "clock_comparison_note": "Registrar el desfase antes de interpretar timestamps del dispositivo.",
        }

    def application_inventory(self) -> Mapping[str, Any]:
        self._ensure_connected()
        code, stdout, stderr = self._run_adb(
            ["shell", "pm", "list", "packages", "-f", "-U"], 120.0
        )
        if code != 0:
            raise AcquisitionError(f"No se pudo obtener el inventario de paquetes: {stderr.strip()}")
        packages: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            match = re.match(r"package:(?P<apk>.+)=(?P<package>[^\s]+)(?:\s+uid:(?P<uid>\d+))?", line.strip())
            if match:
                packages.append({
                    "package": match.group("package"), "apk_path": match.group("apk"),
                    "uid": int(match.group("uid")) if match.group("uid") else None,
                })
        return {
            "created_at_utc": _utc_now(), "device": asdict(self.identity()),
            "packages_count": len(packages), "packages": packages,
        }

    def extract_public_communications(self) -> Mapping[str, Any]:
        """Consulta proveedores Android únicamente cuando adb shell tiene permiso."""
        self._ensure_connected()
        warnings: list[str] = []
        contacts = self._query_content_provider(
            "content://com.android.contacts/data/phones",
            ("display_name", "number", "type", "contact_id"), warnings,
        )
        if not contacts:
            contacts = self._query_content_provider(
                "content://contacts/phones",
                ("display_name", "number", "type", "contact_id"), warnings,
            )
        messages = self._query_content_provider(
            "content://sms",
            ("_id", "thread_id", "address", "date", "date_sent", "type", "read", "body"),
            warnings,
        )
        normalized_messages: list[dict[str, Any]] = []
        for row in messages:
            item = dict(row)
            for field_name in ("date", "date_sent"):
                raw = str(item.get(field_name, ""))
                try:
                    value = int(raw)
                    if value > 0:
                        item[f"{field_name}_utc"] = datetime.fromtimestamp(
                            value / 1000, tz=timezone.utc
                        ).isoformat()
                except (ValueError, OSError, OverflowError):
                    continue
            normalized_messages.append(item)
        unique_contacts = list({
            (str(item.get("contact_id", "")), str(item.get("number", "")), str(item.get("display_name", ""))): item
            for item in contacts
        }.values())
        return {
            "status": "success", "tool": "android_public_communications",
            "acquisition_type": "EXTRACCION_LOGICA_ADB",
            "created_at_utc": _utc_now(), "device": asdict(self.identity()),
            "contacts_count": len(unique_contacts), "sms_count": len(normalized_messages),
            "contacts": unique_contacts, "sms": normalized_messages,
            "warnings": warnings,
            "limitations": (
                "Solo incluye filas que Android concede al usuario adb shell. "
                "No accede a bases privadas, mensajes borrados ni contenido bloqueado."
            ),
        }

    def _query_content_provider(
        self, uri: str, projection: Sequence[str], warnings: list[str]
    ) -> list[dict[str, str]]:
        code, stdout, stderr = self._run_adb(
            ["shell", "content", "query", "--uri", uri, "--projection", ":".join(projection)],
            120.0,
        )
        if code != 0:
            detail = (stderr or stdout).strip()
            warnings.append(f"{uri}: {detail or 'acceso denegado o proveedor no disponible'}")
            return []
        return self._parse_content_rows(stdout)

    @staticmethod
    def _parse_content_rows(output: str) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for line in output.splitlines():
            payload = re.sub(r"^Row:\s*\d+\s*", "", line.strip())
            matches = list(re.finditer(r"(?:^|,\s)([A-Za-z_][A-Za-z0-9_]*)=", payload))
            if not matches:
                continue
            row: dict[str, str] = {}
            for index, match in enumerate(matches):
                start = match.end()
                end = matches[index + 1].start() if index + 1 < len(matches) else len(payload)
                row[match.group(1)] = payload[start:end].rstrip(", ")
            rows.append(row)
        return rows

    def is_locked(self) -> bool:
        self._ensure_connected()
        code, stdout, _ = self._run_adb(
            ["shell", "dumpsys", "window", "policy"], 10.0
        )
        if code != 0:
            return False
        lowered = stdout.lower()
        locked_markers = (
            "mshowinglockscreen=true",
            "iskeyguardshowing=true",
            "keyguardshowing=true",
        )
        return any(marker in lowered for marker in locked_markers)

    def iter_files(self, roots: Sequence[str]) -> Iterator[str]:
        self._ensure_connected()
        seen: set[str] = set()
        for root in roots:
            safe_root = self._validate_remote_path(root)
            code, stdout, stderr = self._run_adb(
                ["shell", "find", safe_root, "-type", "f"], 60.0
            )
            if code not in (0, 1):
                LOGGER.warning("No se pudo enumerar %s: %s", safe_root, stderr.strip())
                continue
            for line in stdout.splitlines():
                path = line.strip()
                suffix = Path(path).suffix.lower()
                if (
                    path
                    and path not in seen
                    and suffix in self._FORENSIC_SUFFIXES
                ):
                    self._validate_remote_path(path)
                    seen.add(path)
                    yield path

    def iter_all_public_files(self) -> Iterator[str]:
        """Enumera archivos públicos sin filtrar extensión para file carving lógico."""
        self._ensure_connected()
        seen: set[str] = set()
        roots: list[str] = []
        # /sdcard normalmente es un alias de /storage/emulated/0. Elegir una sola
        # raíz evita leer cada byte dos veces sin perder cobertura.
        for candidate in ("/storage/emulated/0", "/sdcard"):
            code, _, _ = self._run_adb(
                ["shell", "test", "-d", candidate], 10.0
            )
            if code == 0:
                roots.append(candidate)
                break
        for root in roots:
            safe_root = self._validate_remote_path(root)
            code, stdout, stderr = self._run_adb(
                ["shell", "find", safe_root, "-type", "f"], 300.0
            )
            if code not in (0, 1):
                LOGGER.warning("Ruta pública omitida %s: %s", root, stderr.strip())
                continue
            for line in stdout.splitlines():
                path = line.strip()
                if path and path not in seen:
                    self._validate_remote_path(path)
                    seen.add(path)
                    yield path

    def remote_file_metadata(self, path: str) -> Mapping[str, int] | None:
        safe_path = self._validate_remote_path(path)
        code, stdout, _ = self._run_adb(
            ["shell", "stat", "-c", "%s %Y", safe_path], 15.0
        )
        if code != 0:
            return None
        fields = stdout.strip().split()
        if len(fields) != 2:
            return None
        try:
            return {"size": int(fields[0]), "mtime": int(fields[1])}
        except ValueError:
            return None

    def find_whatsapp_crypt14(self) -> list[str]:
        """Busca Crypt14 recursivamente en almacenamiento público autorizado."""
        self._ensure_connected()
        discovered: set[str] = set()
        for root in self._PUBLIC_STORAGE_ROOTS:
            command = (
                f"find {shlex.quote(root)} -type f "
                "\\( -name '*.db.crypt14' -o -name 'key' \\) 2>/dev/null"
            )
            code, stdout, stderr = self._run_adb(
                ["shell", "sh", "-c", command], 120.0,
            )
            if code not in (0, 1):
                LOGGER.info("Public path unavailable: %s (%s)", root, stderr.strip())
                continue
            for line in stdout.splitlines():
                candidate = line.strip()
                if candidate.startswith(root + "/") and candidate.endswith(".db.crypt14"):
                    self._validate_remote_path(candidate)
                    discovered.add(candidate)
        return sorted(
            discovered,
            key=lambda path: (self._remote_mtime(path), Path(path).name == "msgstore.db.crypt14", path),
            reverse=True,
        )

    def find_whatsapp_pair(self) -> Mapping[str, Any] | None:
        backups = self.find_whatsapp_crypt14()
        if not backups:
            return None
        backup = backups[0]
        parent = str(Path(backup).parent)
        candidates = [
            f"{parent}/key",
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/key",
            "/sdcard/Android/media/com.whatsapp/files/key",
            "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases/key",
            "/storage/emulated/0/Android/media/com.whatsapp/files/key",
        ]
        key_path: str | None = None
        for candidate in dict.fromkeys(candidates):
            self._validate_remote_path(candidate)
            code, stdout, _ = self._run_adb(
                ["shell", "sh", "-c", f"test -f {shlex.quote(candidate)} && echo FOUND"],
                10.0,
            )
            if code == 0 and stdout.strip() == "FOUND":
                key_path = candidate
                break
        return {
            "backup": backup,
            "key": key_path,
            "backup_mtime": self._remote_mtime(backup),
            "backups_found": len(backups),
        }

    def _remote_mtime(self, path: str) -> int:
        self._validate_remote_path(path)
        code, stdout, _ = self._run_adb(
            ["shell", "stat", "-c", "%Y", path], 10.0
        )
        try:
            return int(stdout.strip()) if code == 0 else 0
        except ValueError:
            return 0

    def copy_whatsapp_crypt14(self, remote_path: str, output: Path) -> Mapping[str, Any]:
        if not any(
            remote_path.startswith(root + "/")
            for root in self._WHATSAPP_DATABASE_ROOTS
        ) or not remote_path.endswith(".db.crypt14"):
            raise DevicePermissionError("Ruta Crypt14 fuera de las ubicaciones permitidas")
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_suffix(output.suffix + ".partial")
        digest = hashlib.sha256()
        crc = 0
        size = 0
        command = f"cat -- {shlex.quote(remote_path)}"
        try:
            with partial.open("wb") as stream:
                for chunk, _ in self._stream_file(remote_path, command, 1024 * 1024):
                    stream.write(chunk)
                    digest.update(chunk)
                    crc = zlib.crc32(chunk, crc)
                    size += len(chunk)
            partial.replace(output)
        except (OSError, AcquisitionError, KeyboardInterrupt):
            partial.unlink(missing_ok=True)
            raise
        return {
            "remote_path": remote_path,
            "local_path": str(output),
            "size": size,
            "sha256": digest.hexdigest(),
            "crc32": f"{crc & 0xFFFFFFFF:08x}",
        }

    def copy_public_whatsapp_key(self, remote_path: str, output: Path) -> Mapping[str, Any]:
        safe_path = self._validate_remote_path(remote_path)
        if Path(safe_path).name != "key":
            raise DevicePermissionError("El archivo público seleccionado no se llama key")
        result = dict(self._copy_public_binary(safe_path, output))
        os.chmod(output.resolve(), 0o600)
        return result

    def _copy_public_binary(self, remote_path: str, output: Path) -> Mapping[str, Any]:
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_suffix(output.suffix + ".partial")
        digest = hashlib.sha256()
        crc = 0
        size = 0
        command = f"cat -- {shlex.quote(remote_path)}"
        try:
            with partial.open("wb") as stream:
                for chunk, _ in self._stream_file(remote_path, command, 1024 * 1024):
                    stream.write(chunk)
                    digest.update(chunk)
                    crc = zlib.crc32(chunk, crc)
                    size += len(chunk)
            partial.replace(output)
        except (OSError, AcquisitionError, KeyboardInterrupt):
            partial.unlink(missing_ok=True)
            raise
        return {
            "remote_path": remote_path,
            "local_path": str(output),
            "size": size,
            "sha256": digest.hexdigest(),
            "crc32": f"{crc & 0xFFFFFFFF:08x}",
        }

    def read_file_chunks(
        self, logical_path: str, chunk_size: int
    ) -> Iterator[tuple[bytes, int]]:
        self._ensure_connected()
        if chunk_size <= 0:
            raise ValueError("chunk_size debe ser positivo")
        safe_path = self._validate_remote_path(logical_path)
        command = f"cat -- {shlex.quote(safe_path)}"
        for attempt in range(1, 4):
            emitted = False
            try:
                for chunk, crc in self._stream_file(safe_path, command, chunk_size):
                    emitted = True
                    yield chunk, crc
                return
            except DevicePermissionError:
                raise
            except (HardwareTimeoutError, ProtocolError, AcquisitionError) as error:
                if emitted:
                    raise AcquisitionError(
                        f"Flujo ADB interrumpido después de recibir datos: {safe_path}"
                    ) from error
                if attempt == 3:
                    raise
                LOGGER.warning("ADB STREAM RETRY %d/3 for %s", attempt, safe_path)
                time.sleep(float(attempt))

    def _stream_file(
        self, safe_path: str, shell_command: str, chunk_size: int
    ) -> Iterator[tuple[bytes, int]]:
        command = [self._adb_path]
        if self._serial:
            command.extend(["-s", self._serial])
        command.extend(["exec-out", "sh", "-c", shell_command])
        with tempfile.TemporaryFile() as error_stream:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=error_stream,
                    start_new_session=True,
                )
            except FileNotFoundError as error:
                raise ADBNotFoundError("ADB no fue encontrado") from error
            except PermissionError as error:
                raise DevicePermissionError("ADB no tiene permiso de ejecución") from error
            self._active_streams.add(process)
            try:
                assert process.stdout is not None
                descriptor = process.stdout.fileno()
                while True:
                    readable, _, _ = select.select([descriptor], [], [], 120.0)
                    if not readable:
                        self._terminate_stream(process)
                        raise HardwareTimeoutError(
                            f"ADB sin datos durante 120 segundos: {safe_path}"
                        )
                    chunk = process.stdout.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk, zlib.crc32(chunk) & 0xFFFFFFFF
                try:
                    return_code = process.wait(timeout=10.0)
                except subprocess.TimeoutExpired as error:
                    self._terminate_stream(process)
                    raise HardwareTimeoutError(
                        f"ADB no finalizó la lectura: {safe_path}"
                    ) from error
                if return_code != 0:
                    error_stream.seek(0)
                    message = error_stream.read().decode("utf-8", errors="replace").strip()
                    if "permission denied" in message.lower():
                        raise DevicePermissionError(f"ADB no puede leer {safe_path}")
                    raise AcquisitionError(
                        f"ADB cat falló para {safe_path} (código {return_code}): {message}"
                    )
            finally:
                self._active_streams.discard(process)
                if process.poll() is None:
                    self._terminate_stream(process)
                if process.stdout is not None:
                    process.stdout.close()

    def disconnect(self) -> None:
        for process in tuple(self._active_streams):
            self._terminate_stream(process)
        self._active_streams.clear()
        self._connected = False

    @staticmethod
    def _terminate_stream(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3.0)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                return

    def _getprop(self, name: str) -> str:
        code, stdout, _ = self._run_adb(["shell", "getprop", name], 10.0)
        return stdout.strip() if code == 0 else ""

    def _run_adb(
        self, args: Sequence[str], timeout: float, *, use_serial: bool = True
    ) -> tuple[int, str, str]:
        code, stdout, stderr = self._run_adb_bytes(args, timeout, use_serial=use_serial)
        return (
            code,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )

    def _run_adb_bytes(
        self, args: Sequence[str], timeout: float, *, use_serial: bool = True
    ) -> tuple[int, bytes, bytes]:
        command = [self._adb_path]
        if use_serial and self._serial:
            command.extend(["-s", self._serial])
        command.extend(args)
        try:
            result = subprocess.run(
                command, capture_output=True, timeout=timeout, check=False
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError as error:
            raise ADBNotFoundError("ADB no fue encontrado") from error
        except subprocess.TimeoutExpired as error:
            raise HardwareTimeoutError("El comando ADB agotó el tiempo") from error
        except PermissionError as error:
            raise DevicePermissionError("ADB no tiene permiso de ejecución") from error

    @classmethod
    def _locate_adb(cls, requested: str | None) -> str:
        bundled_adb = (
            Path(__file__).resolve().parent / "platform-tools" / "adb"
        )
        candidates = [requested] if requested else []
        candidates.append(str(bundled_adb))
        detected = shutil.which("adb")
        if detected:
            candidates.append(detected)
        candidates.extend(cls._COMMON_ADB_PATHS)
        candidates.append(
            str(Path.home() / "Library/Android/sdk/platform-tools/adb")
        )
        for candidate in candidates:
            if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return str(Path(candidate).resolve())
        raise ADBNotFoundError(
            "ADB no está instalado. Instala Android Platform Tools o usa --adb-path."
        )

    @staticmethod
    def _parse_devices(output: str) -> list[tuple[str, str]]:
        devices: list[tuple[str, str]] = []
        for line in output.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 2 and not line.startswith("*"):
                devices.append((fields[0], fields[1]))
        return devices

    @staticmethod
    def _validate_remote_path(path: str) -> str:
        if not path.startswith("/") or "\x00" in path or ".." in Path(path).parts:
            raise DevicePermissionError(f"Ruta ADB insegura: {path!r}")
        allowed_roots = (
            "/sdcard",
            "/storage/emulated/0",
            "/data/system/media/thumbnails",
        )
        normalized = path.rstrip("/") or "/"
        if not any(
            normalized == root or normalized.startswith(root + "/")
            for root in allowed_roots
        ):
            raise DevicePermissionError(
                f"Ruta fuera del almacenamiento compartido autorizado: {path}"
            )
        return path

    def _ensure_connected(self) -> None:
        if not self._connected:
            raise ProtocolError("ADB no está conectado")


class SimulatedMobileTransport(MobileTransport):
    """Transporte de laboratorio respaldado por una carpeta local."""

    def __init__(
        self, root: Path, *, locked: bool = False, authorized: bool = True
    ) -> None:
        self._root = root.resolve()
        self._locked = locked
        self._authorized = authorized
        self._connected = False

    def connect(self, timeout_seconds: float) -> None:
        if timeout_seconds <= 0:
            raise HardwareTimeoutError("El timeout debe ser positivo")
        if not self._root.is_dir():
            raise FileNotFoundError(f"No existe el dispositivo simulado: {self._root}")
        self._connected = True

    def exchange(self, request: bytes, timeout_seconds: float) -> bytes:
        self._ensure_connected()
        if timeout_seconds <= 0:
            raise HardwareTimeoutError("Handshake agotado")
        prefix = b"FORENSIC_HELLO:"
        if not request.startswith(prefix):
            raise ProtocolError("Solicitud de handshake desconocida")
        if not self._authorized:
            return b"FORENSIC_DENIED"
        nonce = request[len(prefix) :]
        if len(nonce) != 16:
            raise ProtocolError("Nonce inválido")
        return b"FORENSIC_ACK:" + hashlib.sha256(nonce).digest()

    def identity(self) -> DeviceIdentity:
        self._ensure_connected()
        serial = hashlib.sha256(str(self._root).encode()).hexdigest()[:12].upper()
        return DeviceIdentity(
            serial=f"SIM-{serial}",
            manufacturer="ForensicLab",
            model="Authorized Test Fixture",
            platform="Android-Simulated",
            os_version="14",
            transport="ADB-simulated",
        )

    def is_locked(self) -> bool:
        self._ensure_connected()
        return self._locked

    def iter_files(self, roots: Sequence[str]) -> Iterator[str]:
        self._ensure_ready()
        for root_name in roots:
            root = self._safe_path(root_name)
            if root.is_file():
                yield root.relative_to(self._root).as_posix()
            elif root.is_dir():
                for candidate in sorted(root.rglob("*")):
                    if candidate.is_file():
                        yield candidate.relative_to(self._root).as_posix()

    def read_file_chunks(
        self, logical_path: str, chunk_size: int
    ) -> Iterator[tuple[bytes, int]]:
        self._ensure_ready()
        if chunk_size <= 0:
            raise ValueError("chunk_size debe ser positivo")
        if logical_path.endswith(".deny"):
            raise DevicePermissionError(f"Acceso denegado: {logical_path}")
        if logical_path.endswith(".timeout"):
            raise HardwareTimeoutError(f"Timeout simulado: {logical_path}")
        source = self._safe_path(logical_path)
        try:
            with source.open("rb") as stream:
                index = 0
                while chunk := stream.read(chunk_size):
                    crc = zlib.crc32(chunk) & 0xFFFFFFFF
                    if logical_path.endswith(".badcrc") and index == 0:
                        crc ^= 0xFFFFFFFF
                    yield chunk, crc
                    index += 1
        except PermissionError as error:
            raise DevicePermissionError(str(source)) from error
        except OSError as error:
            raise AcquisitionError(f"Error de lectura: {source}") from error

    def disconnect(self) -> None:
        self._connected = False

    def _safe_path(self, logical_path: str) -> Path:
        relative = Path(logical_path.lstrip("/"))
        if ".." in relative.parts:
            raise DevicePermissionError("Ruta lógica insegura")
        resolved = (self._root / relative).resolve()
        try:
            resolved.relative_to(self._root)
        except ValueError as error:
            raise DevicePermissionError("Ruta fuera del dispositivo") from error
        return resolved

    def _ensure_connected(self) -> None:
        if not self._connected:
            raise ProtocolError("Dispositivo desconectado")

    def _ensure_ready(self) -> None:
        self._ensure_connected()
        if not self._authorized:
            raise DevicePermissionError("Dispositivo no autorizado")
        if self._locked:
            raise DeviceLockedError("El dispositivo debe desbloquearse manualmente")


class ADBFileCarvingEngine:
    """Carving por firmas sobre archivos que Android expone al usuario ADB shell."""

    JPEG_START: Final[bytes] = b"\xff\xd8\xff"
    JPEG_END: Final[bytes] = b"\xff\xd9"
    PNG_START: Final[bytes] = b"\x89PNG\r\n\x1a\n"
    PNG_IEND: Final[bytes] = b"IEND"
    GIF_STARTS: Final[tuple[bytes, ...]] = (b"GIF87a", b"GIF89a")
    GIF_END: Final[bytes] = b"\x3b"

    def __init__(self, transport: RealADBTransport, output_dir: Path) -> None:
        self.transport = transport
        self.output_dir = output_dir.resolve()
        self.maximum_source_bytes = 512 * 1024 * 1024

    def run(self) -> Mapping[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        recovered: list[dict[str, Any]] = []
        hashes: set[str] = set()
        scanned = 0
        remote_paths = list(self.transport.iter_all_public_files())
        total_sources = len(remote_paths)
        for remote_path in remote_paths:
            scanned += 1
            LOGGER.info("CARVING PROGRESS %d/%d %s", scanned, total_sources, remote_path)
            staged_path: Path | None = None
            try:
                before = self._remote_metadata(remote_path)
                staged_path, source_size, source_sha256, source_crc32 = self._stage_source(
                    remote_path
                )
                after = self._remote_metadata(remote_path)
                stability = (
                    "STABLE" if before is not None and before == after
                    else "METADATA_UNAVAILABLE" if before is None or after is None
                    else "CHANGED_DURING_ACQUISITION"
                )
            except (AcquisitionError, OSError) as error:
                LOGGER.warning("CARVING SKIP %s: %s", remote_path, error)
                continue
            try:
                if source_size == 0 or staged_path is None:
                    continue
                with staged_path.open("rb") as staged_stream:
                    with mmap.mmap(staged_stream.fileno(), 0, access=mmap.ACCESS_READ) as payload:
                        for offset, fragment, extension in self._carve(payload):
                            digest = hashlib.sha256(fragment).hexdigest()
                            if digest in hashes or not self._valid_image(fragment, extension):
                                continue
                            hashes.add(digest)
                            destination = self.output_dir / (
                                f"carved_{len(recovered) + 1:06d}_{digest[:12]}.{extension}"
                            )
                            partial = destination.with_suffix(destination.suffix + ".partial")
                            partial.write_bytes(fragment)
                            partial.replace(destination)
                            thumbnail = DeviceHandler._create_thumbnail(
                                destination, self.output_dir / "thumbnails", digest
                            )
                            classification = (
                                "COMPLETE_VISIBLE_FILE"
                                if offset == 0 and len(fragment) == source_size
                                else "EMBEDDED_IMAGE"
                            )
                            item = {
                                "source_path": remote_path,
                                "source_size": source_size,
                                "source_sha256": source_sha256,
                                "source_crc32": source_crc32,
                                "source_metadata_before": before,
                                "source_metadata_after": after,
                                "source_stability": stability,
                                "output_path": str(destination),
                                "thumbnail_path": thumbnail,
                                "offset": offset,
                                "end_offset": offset + len(fragment),
                                "size": len(fragment),
                                "format": extension.upper(),
                                "classification": classification,
                                "deletion_status": "UNDETERMINED",
                                "sha256": digest,
                                "crc32": f"{zlib.crc32(fragment) & 0xFFFFFFFF:08x}",
                                "is_recovered": classification == "EMBEDDED_IMAGE",
                                "recovery_method": "PUBLIC_FILE_SIGNATURE_CARVING",
                            }
                            recovered.append(item)
                            LOGGER.info("CARVED VERIFIED %s SHA256=%s", destination.name, digest)
            finally:
                if staged_path is not None:
                    staged_path.unlink(missing_ok=True)
        format_counts = {
            extension: sum(item["format"] == extension for item in recovered)
            for extension in ("JPG", "PNG", "GIF", "WEBP")
        }
        classification_counts = {
            classification: sum(
                item["classification"] == classification for item in recovered
            )
            for classification in ("COMPLETE_VISIBLE_FILE", "EMBEDDED_IMAGE")
        }
        report = {
            "status": "success",
            "mode": "logical_file_carving",
            "completed_at_utc": _utc_now(),
            "scanned_files": scanned,
            "recovered_count": len(recovered),
            "format_counts": format_counts,
            "classification_counts": classification_counts,
            "output_dir": str(self.output_dir),
            "limitations": (
                "Solo analiza bytes de archivos que ADB shell puede leer; no examina "
                "bloques libres ni demuestra que un fragmento perteneciera a un archivo borrado."
            ),
            "images": recovered,
        }
        ForensicReporter._atomic_json(self.output_dir / "carving_report.json", report)
        self._write_csv(self.output_dir / "carving_manifest.csv", recovered)
        self._write_standard_case(report, recovered)
        return report

    def _write_standard_case(
        self, carving_report: Mapping[str, Any], recovered: Sequence[Mapping[str, Any]]
    ) -> None:
        """Hace que un carving lógico sea verificable/exportable como cualquier caso."""
        reports = self.output_dir / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        try:
            identity = self.transport.identity()
        except (AttributeError, AcquisitionError):
            identity = DeviceIdentity(
                serial="UNAVAILABLE", manufacturer="Android", model="ADB public storage",
                platform="Android", os_version="unknown", transport="ADB-logical-carving",
            )
        manifest: list[dict[str, Any]] = []
        for item in recovered:
            evidence = Path(str(item["output_path"])).resolve()
            thumbnail_value = item.get("thumbnail_path")
            thumbnail = Path(str(thumbnail_value)).resolve() if thumbnail_value else None
            manifest.append({
                "logical_path": f"{item.get('source_path', 'unknown')}@{item.get('offset', 0)}",
                "evidence_path": str(evidence),
                "case_relative_path": evidence.relative_to(self.output_dir.resolve()).as_posix(),
                "size": item.get("size", 0),
                "sha256": item.get("sha256", ""),
                "crc32": item.get("crc32", ""),
                "acquired_at": carving_report.get("completed_at_utc"),
                "thumbnail_path": str(thumbnail) if thumbnail else None,
                "thumbnail_relative_path": (
                    thumbnail.relative_to(self.output_dir.resolve()).as_posix()
                    if thumbnail and thumbnail.is_relative_to(self.output_dir.resolve()) else None
                ),
                "is_recovered": item.get("is_recovered", False),
                "captured_at": None,
                "exif_metadata": {},
                "source_path": item.get("source_path"),
                "source_sha256": item.get("source_sha256"),
                "source_stability": item.get("source_stability"),
                "classification": item.get("classification"),
                "deletion_status": "UNDETERMINED",
            })
        acquisition_id = f"CARVE-{uuid.uuid4()}"
        forensic_report = {
            "schema_version": "3.2",
            "case": {"acquisition_id": acquisition_id,
                     "started_at_utc": carving_report.get("completed_at_utc"),
                     "completed_at_utc": carving_report.get("completed_at_utc")},
            "device": asdict(identity),
            "case_profile": {"source_type": "AUTHORIZED_ADB_PUBLIC_FILE_CARVING"},
            "methodology": {
                "acquisition_type": "AUTHORIZED_LOGICAL_FILE_CARVING",
                "scope": "Archivos públicos legibles por ADB shell",
                "excluded": "Bloques libres, root, sandboxes privados y borrado confirmado",
            },
            "evidence_classification": {
                "ACTIVE_OR_VISIBLE": sum(not bool(item.get("is_recovered")) for item in recovered),
                "LOGICAL_RESIDUAL_OR_EMBEDDED": sum(bool(item.get("is_recovered")) for item in recovered),
                "CONFIRMED_DELETED": 0,
            },
            "manifest": manifest,
            "artifacts": [], "database_analysis": {}, "file_system_tree": {},
            "timeline": [], "smart_links": [], "duplicate_analysis": {},
            "evidence_quality": {"integrity_verified_files": len(manifest),
                                 "recovered_files": sum(bool(item.get("is_recovered")) for item in recovered),
                                 "limitations": carving_report.get("limitations")},
            "parser_registry": [{"id": "logical.signature.carver", "version": "3.2", "status": "active"}],
            "statistics": {"total_files": len(manifest),
                           "total_bytes": sum(int(item.get("size", 0)) for item in recovered)},
            "warnings": [str(carving_report.get("limitations", ""))],
        }
        report_path = reports / "forensic_report.json"
        ForensicReporter._atomic_json(report_path, forensic_report)
        raw_events = [
            {"timestamp": carving_report.get("completed_at_utc"), "event": "LOGICAL_CARVING_STARTED"},
            {"timestamp": carving_report.get("completed_at_utc"), "event": "LOGICAL_CARVING_COMPLETED"},
        ]
        previous = "0" * 64
        events = []
        for event in raw_events:
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest()
            events.append({**event, "previous_hash": previous, "event_hash": event_hash})
            previous = event_hash
        ForensicReporter._atomic_json(reports / "chain_of_custody.json", {
            "acquisition_id": acquisition_id, "action": "AUTHORIZED_LOGICAL_FILE_CARVING",
            "audit_chain_head": previous, "events": events,
        })
        ForensicReporter._atomic_json(reports / "examiner_annotations.json", {"version": 1, "annotations": []})
        ForensicReporter._write_master_manifest(reports / "case_master_manifest.json", self.output_dir)

    @staticmethod
    def _write_csv(path: Path, recovered: Sequence[Mapping[str, Any]]) -> None:
        columns = (
            "output_path", "source_path", "offset", "size", "source_size",
            "end_offset", "format", "classification", "deletion_status",
            "source_stability", "source_sha256", "source_crc32",
            "sha256", "crc32", "recovery_method",
        )
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(recovered)

    def _remote_metadata(self, remote_path: str) -> Mapping[str, int] | None:
        method = getattr(self.transport, "remote_file_metadata", None)
        return method(remote_path) if callable(method) else None

    def _stage_source(self, remote_path: str) -> tuple[Path, int, str, str]:
        digest = hashlib.sha256()
        crc = 0
        size = 0
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".source-scan-", dir=self.output_dir, delete=False
        ) as stream:
            staged = Path(stream.name)
            try:
                for chunk, _ in self.transport.read_file_chunks(remote_path, 1024 * 1024):
                    size += len(chunk)
                    if size > self.maximum_source_bytes:
                        raise AcquisitionError("archivo superior al límite configurado de 512 MiB")
                    stream.write(chunk)
                    digest.update(chunk)
                    crc = zlib.crc32(chunk, crc)
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                staged.unlink(missing_ok=True)
                raise
        return staged, size, digest.hexdigest(), f"{crc & 0xFFFFFFFF:08x}"

    @classmethod
    def _carve(cls, payload: bytes) -> Iterator[tuple[int, bytes, str]]:
        cursor = 0
        while cursor < len(payload):
            starts = [
                (position, kind)
                for position, kind in (
                    (payload.find(cls.JPEG_START, cursor), "jpg"),
                    (payload.find(cls.PNG_START, cursor), "png"),
                    (payload.find(b"GIF87a", cursor), "gif"),
                    (payload.find(b"GIF89a", cursor), "gif"),
                )
                if position >= 0
            ]
            webp = cls._find_webp(payload, cursor)
            if webp >= 0:
                starts.append((webp, "webp"))
            if not starts:
                return
            start, kind = min(starts)
            if kind == "jpg":
                marker = payload.find(cls.JPEG_END, start + 3)
                if marker < 0:
                    cursor = start + 3
                    continue
                end = marker + 2
            elif kind == "png":
                marker = payload.find(cls.PNG_IEND, start + 8)
                if marker < 4 or marker + 8 > len(payload):
                    cursor = start + 8
                    continue
                end = marker + 8
            elif kind == "gif":
                marker = payload.find(cls.GIF_END, start + 6)
                if marker < 0:
                    cursor = start + 6
                    continue
                end = marker + 1
            else:
                declared_size = int.from_bytes(payload[start + 4:start + 8], "little") + 8
                end = start + declared_size
                if declared_size < 12 or end > len(payload):
                    cursor = start + 12
                    continue
            yield start, payload[start:end], kind
            cursor = end

    @staticmethod
    def _find_webp(payload: bytes, cursor: int) -> int:
        position = payload.find(b"RIFF", cursor)
        while position >= 0:
            if position + 12 <= len(payload) and payload[position + 8:position + 12] == b"WEBP":
                return position
            position = payload.find(b"RIFF", position + 4)
        return -1

    @staticmethod
    def _valid_image(fragment: bytes, extension: str) -> bool:
        if len(fragment) < 64:
            return False
        if Image is None:
            return (
                extension == "jpg" and fragment.endswith(b"\xff\xd9")
                or extension == "png" and b"IEND" in fragment[-16:]
                or extension == "gif" and fragment.startswith(ADBFileCarvingEngine.GIF_STARTS)
                and fragment.endswith(b"\x3b")
                or extension == "webp" and fragment.startswith(b"RIFF")
                and fragment[8:12] == b"WEBP"
            )
        try:
            with Image.open(BytesIO(fragment)) as image:
                expected = {"jpg": "JPEG", "png": "PNG", "gif": "GIF", "webp": "WEBP"}[extension]
                if image.format != expected or image.width < 1 or image.height < 1:
                    return False
                image.verify()
            return True
        except (UnidentifiedImageError, OSError):
            return False


class DeviceHandler:
    def __init__(self, transport: MobileTransport, timeout_seconds: float = 10.0) -> None:
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._state = DeviceState.DISCONNECTED
        self._identity: DeviceIdentity | None = None

    @property
    def state(self) -> DeviceState:
        return self._state

    @property
    def transport(self) -> MobileTransport:
        if self._state is not DeviceState.READY:
            raise ProtocolError(f"Dispositivo no preparado: {self._state.value}")
        return self._transport

    def connect(self) -> DeviceIdentity:
        try:
            self._transport.connect(self._timeout_seconds)
            self._state = DeviceState.CONNECTED
            self._perform_handshake()
            self._identity = self._transport.identity()
            if self._transport.is_locked():
                self._state = DeviceState.LOCKED
                raise DeviceLockedError("Adquisición cancelada: dispositivo bloqueado")
            self._state = DeviceState.READY
            return self._identity
        except (HardwareTimeoutError, DevicePermissionError, DeviceLockedError, ProtocolError):
            if self._state is not DeviceState.LOCKED:
                self._state = DeviceState.ERROR
            self._safe_disconnect()
            raise
        except PermissionError as error:
            self._state = DeviceState.ERROR
            self._safe_disconnect()
            raise DevicePermissionError("Permisos insuficientes") from error
        except OSError as error:
            self._state = DeviceState.ERROR
            self._safe_disconnect()
            raise AcquisitionError(
                f"Fallo del sistema operativo durante la conexión: {error}"
            ) from error

    def acquire_logical_files(
        self, roots: Sequence[str], output_dir: Path
    ) -> tuple[list[FileManifestEntry], list[str]]:
        manifest: list[FileManifestEntry] = []
        warnings: list[str] = []
        if output_dir.is_symlink():
            raise DevicePermissionError("La carpeta de evidencia no puede ser un enlace simbólico")
        output_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = output_dir.parent / "acquisition_checkpoint.json"
        if checkpoint_path.is_symlink():
            raise DevicePermissionError("El checkpoint no puede ser un enlace simbólico")
        checkpoint: dict[str, Any] = {"version": 1, "files": {}, "status": "running"}
        if checkpoint_path.is_file():
            try:
                loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("files"), dict):
                    checkpoint = loaded
                    checkpoint["status"] = "resumed"
                    LOGGER.info("RESUMING checkpoint with %d verified files", len(checkpoint["files"]))
            except (OSError, json.JSONDecodeError):
                LOGGER.warning("Checkpoint inválido; se iniciará una verificación nueva")
        try:
            for logical_path in self.transport.iter_files(roots):
                try:
                    saved = checkpoint["files"].get(logical_path)
                    if isinstance(saved, dict):
                        try:
                            resumed = FileManifestEntry(**saved)
                        except (TypeError, ValueError):
                            LOGGER.warning("Checkpoint entry rejected for %s: invalid schema", logical_path)
                        else:
                            existing = Path(resumed.evidence_path)
                            if (
                                resumed.logical_path == logical_path
                                and len(resumed.sha256) == 64
                                and self._is_safe_checkpoint_file(existing, output_dir.parent)
                                and existing.stat().st_size == resumed.size
                                and self._sha256_file(existing) == resumed.sha256
                            ):
                                LOGGER.info("RESUME VERIFIED %s", logical_path)
                                manifest.append(resumed)
                                continue
                    LOGGER.info("ACQUIRING %s", logical_path)
                    manifest.append(self._acquire_one(logical_path, output_dir))
                    LOGGER.info(
                        "VERIFIED %s SHA256=%s",
                        logical_path,
                        manifest[-1].sha256,
                    )
                    checkpoint["files"][logical_path] = asdict(manifest[-1])
                    checkpoint["updated_at"] = _utc_now()
                    self._atomic_checkpoint(checkpoint_path, checkpoint)
                except (
                    DevicePermissionError,
                    HardwareTimeoutError,
                    CRCMismatchError,
                ) as error:
                    warning = f"{logical_path}: {error}"
                    LOGGER.warning(warning)
                    warnings.append(warning)
        except (DevicePermissionError, DeviceLockedError, ProtocolError):
            raise
        except OSError as error:
            raise AcquisitionError(f"Falló la adquisición lógica: {error}") from error
        checkpoint["status"] = "complete_with_warnings" if warnings else "complete"
        checkpoint["completed_at"] = _utc_now()
        self._atomic_checkpoint(checkpoint_path, checkpoint)
        return manifest, warnings

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _is_safe_checkpoint_file(path: Path, case_root: Path) -> bool:
        """Impide que un checkpoint manipulado introduzca evidencia externa."""
        try:
            if not path.is_file() or path.is_symlink():
                return False
            resolved = path.resolve(strict=True)
            root = case_root.resolve(strict=True)
            resolved.relative_to(root)
            return any(part in {"evidence", "recovered_deleted"} for part in resolved.parts)
        except (OSError, ValueError):
            return False

    @staticmethod
    def _atomic_checkpoint(path: Path, payload: Mapping[str, Any]) -> None:
        partial = path.with_suffix(".partial")
        if path.is_symlink() or partial.is_symlink():
            raise DevicePermissionError("El checkpoint no puede ser un enlace simbólico")
        partial.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(partial, 0o600)
        partial.replace(path)

    def disconnect(self) -> None:
        try:
            self._transport.disconnect()
        except OSError as error:
            LOGGER.warning("Error durante la desconexión: %s", error)
        finally:
            self._state = DeviceState.DISCONNECTED

    def _perform_handshake(self) -> None:
        nonce = uuid.uuid4().bytes
        response = self._transport.exchange(
            b"FORENSIC_HELLO:" + nonce, self._timeout_seconds
        )
        expected = b"FORENSIC_ACK:" + hashlib.sha256(nonce).digest()
        if response != expected:
            raise ProtocolError("Falló la verificación criptográfica del handshake")
        self._state = DeviceState.AUTHORIZED

    def _safe_disconnect(self) -> None:
        self.disconnect()

    def _acquire_one(self, logical_path: str, output_dir: Path) -> FileManifestEntry:
        relative = Path(logical_path.lstrip("/"))
        if ".." in relative.parts:
            raise DevicePermissionError("Ruta de evidencia insegura")
        lowered_path = logical_path.lower()
        is_recovered = (
            "/.thumbnails/" in lowered_path
            or "/cache/" in lowered_path
            or "/.cache/" in lowered_path
            or "/.trash/" in lowered_path
            or "/tmp/" in lowered_path
            or lowered_path.endswith(".deleted")
            or lowered_path.startswith("/data/system/media/thumbnails")
        )
        destination_root = (
            output_dir.parent / "recovered_deleted"
            if is_recovered
            else output_dir
        )
        output = (destination_root / relative).resolve()
        output.relative_to(destination_root.resolve())
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_suffix(output.suffix + ".partial")
        sha256_hasher = hashlib.sha256()
        crc32_total = 0
        total_size = 0
        try:
            with partial.open("wb") as stream:
                for index, (chunk, expected_crc) in enumerate(
                    self.transport.read_file_chunks(logical_path, 1024 * 1024)
                ):
                    actual_crc = zlib.crc32(chunk) & 0xFFFFFFFF
                    if actual_crc != expected_crc:
                        raise CRCMismatchError(
                            f"CRC inválido en bloque {index}: "
                            f"{actual_crc:08x} != {expected_crc:08x}"
                        )
                    stream.write(chunk)
                    sha256_hasher.update(chunk)
                    crc32_total = zlib.crc32(chunk, crc32_total)
                    total_size += len(chunk)
            partial.replace(output)
        except (OSError, AcquisitionError, KeyboardInterrupt):
            partial.unlink(missing_ok=True)
            raise
        thumbnail_path: str | None = None
        captured_at: str | None = None
        exif_metadata: Mapping[str, Any] = {}
        if output.suffix.lower() in {
            ".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif", ".dng", ".deleted"
        }:
            thumbnail_path = self._create_thumbnail(
                output,
                output_dir.parent / "thumbnails",
                sha256_hasher.hexdigest(),
            )
            captured_at = self._photo_capture_time(output)
            exif_metadata = self._photo_metadata(output)
        return FileManifestEntry(
            logical_path=logical_path,
            evidence_path=str(output),
            size=total_size,
            sha256=sha256_hasher.hexdigest(),
            crc32=f"{crc32_total & 0xFFFFFFFF:08x}",
            acquired_at=_utc_now(),
            thumbnail_path=thumbnail_path,
            is_recovered=is_recovered,
            captured_at=captured_at,
            exif_metadata=exif_metadata,
            case_relative_path=output.relative_to(output_dir.parent.resolve()).as_posix(),
            thumbnail_relative_path=(
                Path(thumbnail_path).resolve().relative_to(output_dir.parent.resolve()).as_posix()
                if thumbnail_path else None
            ),
        )

    @staticmethod
    def _create_thumbnail(source: Path, thumbnail_dir: Path, digest: str) -> str | None:
        if Image is None or ImageOps is None:
            LOGGER.warning("Pillow no está disponible; no se generó miniatura para %s", source)
            return None
        thumbnail_dir.mkdir(parents=True, exist_ok=True)
        target = thumbnail_dir / f"{digest[:16]}.jpg"
        partial = target.with_suffix(".partial")
        try:
            with Image.open(source) as original:
                normalized = ImageOps.exif_transpose(original).convert("RGB")
                normalized.thumbnail((150, 150), Image.Resampling.LANCZOS)
                canvas = Image.new("RGB", (150, 150), (12, 16, 18))
                position = (
                    (150 - normalized.width) // 2,
                    (150 - normalized.height) // 2,
                )
                canvas.paste(normalized, position)
                canvas.save(partial, "JPEG", quality=88, optimize=True)
            partial.replace(target)
            return str(target)
        except (UnidentifiedImageError, OSError) as error:
            partial.unlink(missing_ok=True)
            LOGGER.warning("No se pudo generar miniatura de %s: %s", source, error)
            return None

    @staticmethod
    def _photo_capture_time(source: Path) -> str | None:
        if Image is None:
            return None
        try:
            with Image.open(source) as image:
                exif = image.getexif()
                value = exif.get(36867) or exif.get(306)
            if not isinstance(value, str):
                return None
            return datetime.strptime(value, "%Y:%m:%d %H:%M:%S").isoformat()
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _photo_metadata(source: Path) -> Mapping[str, Any]:
        """Extrae EXIF legible sin modificar la evidencia original."""
        if Image is None:
            return {}
        tag_names = {
            256: "width", 257: "height", 271: "camera_make", 272: "camera_model",
            274: "orientation", 305: "software", 306: "modified_at",
            36867: "captured_at", 33434: "exposure_time", 33437: "f_number",
            34855: "iso", 37386: "focal_length",
        }
        metadata: dict[str, Any] = {}
        try:
            with Image.open(source) as image:
                metadata["pixel_width"] = image.width
                metadata["pixel_height"] = image.height
                metadata["format"] = image.format
                exif = image.getexif()
                for tag, name in tag_names.items():
                    value = exif.get(tag)
                    if value is not None:
                        metadata[name] = str(value)
                try:
                    gps = exif.get_ifd(34853)
                    if gps:
                        metadata["gps_present"] = True
                        metadata["gps_raw"] = {
                            str(key): str(value) for key, value in gps.items()
                        }
                        def decimal(values: Any, reference: Any) -> float | None:
                            try:
                                degrees, minutes, seconds = (float(value) for value in values)
                                result = degrees + minutes / 60 + seconds / 3600
                                return -result if str(reference) in {"S", "W"} else result
                            except (TypeError, ValueError, ZeroDivisionError):
                                return None
                        latitude = decimal(gps.get(2), gps.get(1))
                        longitude = decimal(gps.get(4), gps.get(3))
                        if latitude is not None and longitude is not None:
                            metadata["latitude"] = latitude
                            metadata["longitude"] = longitude
                except (AttributeError, KeyError, TypeError, ValueError):
                    metadata["gps_present"] = False
        except (UnidentifiedImageError, OSError):
            return {}
        return metadata


class FileExtractor:
    CRITICAL_ROOTS: Final[tuple[str, ...]] = (
        "data/data/com.android.providers.telephony/databases",
        "data/data/com.whatsapp/databases",
        "data/data/com.android.providers.contacts/databases",
    )

    ADB_PUBLIC_ROOTS: Final[tuple[str, ...]] = (
        "/sdcard/DCIM",
        "/sdcard/Pictures",
        "/sdcard/Download",
        "/sdcard/Android/data/com.whatsapp/databases",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/WhatsApp/Databases",
        "/sdcard/.thumbnails",
        "/sdcard/DCIM/.thumbnails",
        "/sdcard/Pictures/.thumbnails",
        "/sdcard/Android/data/com.whatsapp/cache",
        "/sdcard/Android/data/com.whatsapp/files/.cache",
        "/sdcard/WhatsApp/Media/.Trash",
        "/data/system/media/thumbnails",
    )

    def __init__(
        self,
        device: DeviceHandler,
        evidence_dir: Path,
        roots: Sequence[str] | None = None,
    ) -> None:
        self._device = device
        self._evidence_dir = evidence_dir
        self._roots = tuple(roots or self.CRITICAL_ROOTS)

    def extract(self) -> tuple[list[FileManifestEntry], list[str]]:
        return self._device.acquire_logical_files(
            self._roots, self._evidence_dir
        )


class DatabaseParser:
    SIGNATURES: Final[Mapping[ArtifactType, tuple[frozenset[str], ...]]] = {
        ArtifactType.SMS: (frozenset({"address", "body", "date"}),),
        ArtifactType.WHATSAPP: (
            frozenset({"key_remote_jid", "data", "timestamp"}),
        ),
        ArtifactType.CALL: (frozenset({"number", "date", "duration"}),),
        ArtifactType.CONTACT: (
            frozenset({"display_name", "number"}),
            frozenset({"name", "phone"}),
        ),
    }

    def parse(
        self, manifest: Sequence[FileManifestEntry]
    ) -> tuple[list[ParsedArtifact], list[str]]:
        artifacts: list[ParsedArtifact] = []
        warnings: list[str] = []
        for entry in manifest:
            path = Path(entry.evidence_path)
            if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
                continue
            try:
                artifacts.extend(self._parse_database(path, entry.logical_path))
            except (CorruptDataError, DevicePermissionError) as error:
                warnings.append(f"{entry.logical_path}: {error}")
        return artifacts, warnings

    def _parse_database(self, path: Path, source: str) -> list[ParsedArtifact]:
        try:
            with path.open("rb") as stream:
                header = stream.read(16)
        except OSError as error:
            raise CorruptDataError(f"No se pudo leer SQLite: {error}") from error
        if header != b"SQLite format 3\x00":
            raise CorruptDataError("Cabecera SQLite inválida")
        artifacts: list[ParsedArtifact] = []
        uri = f"{path.as_uri()}?mode=ro&immutable=1"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                connection.row_factory = sqlite3.Row
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise CorruptDataError("Falló PRAGMA integrity_check")
                tables = connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                for table_row in tables:
                    table = str(table_row[0])
                    quoted = '"' + table.replace('"', '""') + '"'
                    columns = frozenset(
                        str(row[1]).lower()
                        for row in connection.execute(f"PRAGMA table_info({quoted})")
                    )
                    artifact_type = self._classify(columns)
                    table_lower = table.lower()
                    if artifact_type is ArtifactType.GENERIC:
                        if table_lower in {"message", "messages", "chat", "chats"}:
                            artifact_type = ArtifactType.WHATSAPP
                        elif table_lower in {"contact", "contacts", "wa_contacts"}:
                            artifact_type = ArtifactType.CONTACT
                    if artifact_type is ArtifactType.GENERIC:
                        continue
                    for row in connection.execute(f"SELECT * FROM {quoted} LIMIT 5000"):
                        artifacts.append(
                            ParsedArtifact(
                                artifact_type=artifact_type,
                                source_database=source,
                                source_table=table,
                                record=self._normalize(dict(row)),
                            )
                        )
        except sqlite3.DatabaseError as error:
            raise CorruptDataError(f"SQLite corrupta: {error}") from error
        except PermissionError as error:
            raise DevicePermissionError(str(path)) from error
        return artifacts

    def _classify(self, columns: frozenset[str]) -> ArtifactType:
        for artifact_type, signatures in self.SIGNATURES.items():
            if any(signature.issubset(columns) for signature in signatures):
                return artifact_type
        return ArtifactType.GENERIC

    @staticmethod
    def _normalize(record: Mapping[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in record.items():
            name = key.strip().lower()
            if isinstance(value, bytes):
                normalized[name] = {
                    "length": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
            elif isinstance(value, str):
                normalized[name] = value.replace("\x00", "").strip()
            elif isinstance(value, (int, float)) and any(
                marker in name for marker in ("date", "time", "timestamp")
            ):
                seconds = float(value) / 1000 if value > 10_000_000_000 else float(value)
                try:
                    normalized[name] = datetime.fromtimestamp(
                        seconds, timezone.utc
                    ).isoformat()
                except (ValueError, OverflowError, OSError):
                    normalized[name] = value
            else:
                normalized[name] = value
        return normalized


class ForensicReporter:
    def __init__(self, report_dir: Path) -> None:
        self._report_dir = report_dir

    def generate(self, result: AcquisitionResult) -> dict[str, Path]:
        if self._report_dir.is_symlink():
            raise DevicePermissionError("La carpeta de reportes no puede ser un enlace simbólico")
        self._report_dir.mkdir(parents=True, exist_ok=True)
        json_path = self._report_dir / "forensic_report.json"
        artifacts_path = self._report_dir / "artifacts.csv"
        manifest_path = self._report_dir / "manifest.csv"
        html_path = self._report_dir / "forensic_report.html"
        custody_path = self._report_dir / "chain_of_custody.json"
        index_path = self._report_dir / "forensic_index.sqlite"
        annotations_path = self._report_dir / "examiner_annotations.json"
        geojson_path = self._report_dir / "photo_locations.geojson"
        kml_path = self._report_dir / "photo_locations.kml"
        master_manifest_path = self._report_dir / "case_master_manifest.json"
        profile_path = self._report_dir.parent / "case_profile.json"
        case_profile: Mapping[str, Any] = {}
        if profile_path.is_file():
            try:
                loaded_profile = json.loads(profile_path.read_text(encoding="utf-8"))
                if isinstance(loaded_profile, dict):
                    case_profile = loaded_profile
            except (OSError, json.JSONDecodeError) as error:
                result.warnings.append(f"Perfil del caso ilegible: {error}")
        artifacts_payload = [
            {
                "artifact_type": item.artifact_type.value,
                "source_database": item.source_database,
                "source_table": item.source_table,
                "record": item.record,
            }
            for item in result.artifacts
        ]
        file_tree = self._build_file_tree(result.manifest)
        timeline = self._build_timeline(result.manifest, result.artifacts)
        smart_links = self._build_smart_links(result.artifacts, result.manifest)
        duplicate_analysis = self._duplicate_analysis(result.manifest)
        quality = self._evidence_quality(result.manifest, result.artifacts, result.warnings)
        statistics = self._statistics(result.manifest, result.artifacts)
        evidence_classification = {
            "ACTIVE_LOGICAL_FILE": sum(not item.is_recovered for item in result.manifest),
            "LOGICAL_RESIDUAL_COPY": sum(item.is_recovered for item in result.manifest),
            "CONFIRMED_DELETED": 0,
            "note": (
                "[!REC] significa copia residual o caché todavía legible por ADB. "
                "No demuestra borrado ni recuperación desde espacio no asignado."
            ),
        }
        payload = {
            "case": {
                "acquisition_id": result.acquisition_id,
                "started_at": result.started_at,
                "completed_at": result.completed_at,
            },
            "case_profile": case_profile,
            "methodology": {
                "acquisition_type": "AUTHORIZED_LOGICAL_ADB",
                "tool": "Forensic Mobile Lab 3.2",
                "hashes": ["SHA-256", "CRC32"],
                "scope": "Datos expuestos al usuario adb shell y almacenamiento compartido autorizado.",
                "excluded": "No evade bloqueo, cifrado, sandbox, root ni bootloader; no lee espacio no asignado.",
                "validation": "Manifiesto reproducible, firma Ed25519 externa y verificador independiente.",
            },
            "device": asdict(result.device),
            "photos_count": sum(
                Path(entry.evidence_path).suffix.lower()
                in {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif", ".dng"}
                for entry in result.manifest
            ),
            "recovered_photos_count": sum(
                entry.is_recovered and entry.thumbnail_path is not None
                for entry in result.manifest
            ),
            "thumbnails_path": str(self._report_dir.parent / "thumbnails"),
            "Active_Photos": [
                asdict(entry)
                for entry in result.manifest
                if not entry.is_recovered
                and Path(entry.evidence_path).suffix.lower()
                in {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif", ".dng"}
            ],
            "Recovered_Deleted_Photos": [
                asdict(entry)
                for entry in result.manifest
                if entry.is_recovered and entry.thumbnail_path is not None
            ],
            "recovery_limitations": (
                "Recuperación Lógica: solo copias residuales todavía existentes "
                "y legibles por ADB; no realiza carving ni lee espacio libre."
            ),
            "evidence_classification": evidence_classification,
            "warnings": result.warnings,
            "manifest": [asdict(item) for item in result.manifest],
            "artifacts": artifacts_payload,
            "database_analysis": {
                "total_records": len(result.artifacts),
                "counts": {
                    kind.value: sum(item.artifact_type is kind for item in result.artifacts)
                    for kind in ArtifactType
                    if kind is not ArtifactType.GENERIC
                },
                "tables": sorted(
                    {
                        f"{item.source_database}:{item.source_table}"
                        for item in result.artifacts
                    }
                ),
                "sample_records": artifacts_payload[:25],
            },
            "file_system_tree": file_tree,
            "timeline": timeline,
            "smart_links": smart_links,
            "duplicate_analysis": duplicate_analysis,
            "evidence_quality": quality,
            "parser_registry": [
                {"id": "android.sms", "version": "1.0", "status": "active", "artifact": "sms"},
                {"id": "android.calls", "version": "1.0", "status": "active", "artifact": "call"},
                {"id": "android.contacts", "version": "1.0", "status": "active", "artifact": "contact"},
                {"id": "whatsapp.sqlite", "version": "1.0", "status": "active", "artifact": "whatsapp"},
                {"id": "generic.sqlite", "version": "1.0", "status": "active", "artifact": "generic"},
            ],
            "statistics": statistics,
        }
        self._atomic_json(json_path, payload)
        self._artifacts_csv(artifacts_path, result.artifacts)
        self._manifest_csv(manifest_path, result.manifest)
        raw_events = [
            {"timestamp": result.started_at, "event": "ACQUISITION_STARTED"},
            {"timestamp": result.completed_at, "event": "ACQUISITION_COMPLETED"},
            {"timestamp": _utc_now(), "event": "REPORTS_HASHED"},
        ]
        chained_events: list[dict[str, Any]] = []
        previous_hash = "0" * 64
        for event in raw_events:
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(
                (previous_hash + canonical).encode("utf-8")
            ).hexdigest()
            chained_events.append({**event, "previous_hash": previous_hash, "event_hash": event_hash})
            previous_hash = event_hash
        custody = {
            "acquisition_id": result.acquisition_id,
            "created_at_utc": _utc_now(),
            "tool": "Forensic Mobile Lab",
            "action": "AUTHORIZED_LOGICAL_ACQUISITION",
            "files": len(result.manifest),
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "report_sha256": hashlib.sha256(json_path.read_bytes()).hexdigest(),
            "audit_chain_head": previous_hash,
            "events": chained_events,
        }
        self._atomic_json(custody_path, custody)
        html_path.write_text(self._html_report(payload, custody), encoding="utf-8")
        self._build_search_index(index_path, payload)
        self._write_geo_exports(geojson_path, kml_path, result.manifest)
        if not annotations_path.exists():
            self._atomic_json(annotations_path, {"version": 1, "annotations": []})
        self._write_master_manifest(master_manifest_path, self._report_dir.parent)
        return {
            "json": json_path,
            "html": html_path,
            "artifacts": artifacts_path,
            "manifest": manifest_path,
            "chain_of_custody": custody_path,
            "search_index": index_path,
            "annotations": annotations_path,
            "geojson": geojson_path,
            "kml": kml_path,
            "case_master_manifest": master_manifest_path,
        }

    @staticmethod
    def _write_master_manifest(path: Path, case_root: Path) -> None:
        entries: list[dict[str, Any]] = []
        root = case_root.resolve()
        for candidate in sorted(root.rglob("*")):
            if candidate.is_symlink():
                raise DevicePermissionError(
                    f"El expediente contiene un enlace simbólico no permitido: {candidate}"
                )
            if not candidate.is_file() or candidate == path:
                continue
            try:
                candidate.resolve(strict=True).relative_to(root)
            except ValueError as error:
                raise DevicePermissionError("Se detectó una ruta fuera del expediente") from error
            relative = candidate.relative_to(root)
            if (
                ".ui_cache" in relative.parts
                or candidate.suffix == ".partial"
                or relative.as_posix() == "reports/integrity_verification.json"
                or relative.as_posix() == "reports/case_signature.json"
            ):
                continue
            digest = hashlib.sha256()
            size = 0
            with candidate.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            entries.append({
                "path": relative.as_posix(),
                "size": size,
                "sha256": digest.hexdigest(),
            })
        payload = {
            "version": 1,
            "created_at_utc": _utc_now(),
            "case_root": str(root),
            "files": entries,
            "files_count": len(entries),
        }
        ForensicReporter._atomic_json(path, payload)

    @staticmethod
    def _statistics(
        manifest: Sequence[FileManifestEntry], artifacts: Sequence[ParsedArtifact]
    ) -> Mapping[str, Any]:
        by_extension: dict[str, int] = {}
        by_artifact: dict[str, int] = {}
        for entry in manifest:
            extension = Path(entry.evidence_path).suffix.lower() or "[no extension]"
            by_extension[extension] = by_extension.get(extension, 0) + 1
        for artifact in artifacts:
            key = artifact.artifact_type.value
            by_artifact[key] = by_artifact.get(key, 0) + 1
        return {
            "files_by_extension": dict(sorted(by_extension.items())),
            "artifacts_by_type": dict(sorted(by_artifact.items())),
            "total_bytes": sum(entry.size for entry in manifest),
            "active_files": sum(not entry.is_recovered for entry in manifest),
            "recovered_files": sum(entry.is_recovered for entry in manifest),
        }

    @staticmethod
    def _write_geo_exports(
        geojson_path: Path, kml_path: Path, manifest: Sequence[FileManifestEntry]
    ) -> None:
        points: list[dict[str, Any]] = []
        placemarks: list[str] = []
        for entry in manifest:
            latitude = entry.exif_metadata.get("latitude")
            longitude = entry.exif_metadata.get("longitude")
            if not isinstance(latitude, (int, float)) or not isinstance(longitude, (int, float)):
                continue
            points.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [longitude, latitude]},
                "properties": {"path": entry.logical_path, "sha256": entry.sha256,
                               "captured_at": entry.captured_at},
            })
            placemarks.append(
                f"<Placemark><name>{html.escape(Path(entry.logical_path).name)}</name>"
                f"<description>SHA-256: {entry.sha256}</description>"
                f"<Point><coordinates>{longitude},{latitude},0</coordinates></Point></Placemark>"
            )
        ForensicReporter._atomic_json(
            geojson_path, {"type": "FeatureCollection", "features": points}
        )
        kml_path.write_text(
            "<?xml version='1.0' encoding='UTF-8'?><kml xmlns='http://www.opengis.net/kml/2.2'><Document>"
            + "".join(placemarks) + "</Document></kml>", encoding="utf-8"
        )

    @staticmethod
    def _duplicate_analysis(
        manifest: Sequence[FileManifestEntry],
    ) -> Mapping[str, Any]:
        exact: dict[str, list[str]] = {}
        visual: dict[str, list[str]] = {}
        for entry in manifest:
            exact.setdefault(entry.sha256, []).append(entry.logical_path)
            if Image is None or not entry.thumbnail_path:
                continue
            try:
                with Image.open(entry.thumbnail_path) as image:
                    gray = image.convert("L").resize((9, 8))
                    pixels = list(gray.getdata())
                bits = [pixels[row * 9 + col] > pixels[row * 9 + col + 1]
                        for row in range(8) for col in range(8)]
                value = sum((1 << index) for index, bit in enumerate(bits) if bit)
                visual.setdefault(f"{value:016x}", []).append(entry.logical_path)
            except (OSError, ValueError):
                continue
        return {
            "exact_groups": [
                {"sha256": digest, "paths": paths}
                for digest, paths in exact.items() if len(paths) > 1
            ],
            "visual_groups": [
                {"dhash": digest, "paths": paths}
                for digest, paths in visual.items() if len(paths) > 1
            ],
        }

    @staticmethod
    def _evidence_quality(
        manifest: Sequence[FileManifestEntry],
        artifacts: Sequence[ParsedArtifact],
        warnings: Sequence[str],
    ) -> Mapping[str, Any]:
        photos = [entry for entry in manifest if Path(entry.evidence_path).suffix.lower()
                  in {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif", ".dng"}]
        return {
            "integrity_verified_files": len(manifest),
            "permission_or_read_warnings": len(warnings),
            "photos_without_exif": sum(not entry.exif_metadata for entry in photos),
            "recovered_files": sum(entry.is_recovered for entry in manifest),
            "sqlite_records": len(artifacts),
            "empty_files": sum(entry.size == 0 for entry in manifest),
            "coverage": "ADB_LOGICAL_AUTHORIZED",
            "limitations": "No incluye sandboxes privados, memoria sin asignar ni carving físico.",
        }

    @staticmethod
    def _build_search_index(path: Path, payload: Mapping[str, Any]) -> None:
        partial = path.with_suffix(".partial")
        partial.unlink(missing_ok=True)
        try:
            with sqlite3.connect(partial) as connection:
                connection.execute(
                    "CREATE VIRTUAL TABLE search USING fts5(kind, source, content)"
                )
                for item in payload.get("manifest", []):
                    connection.execute(
                        "INSERT INTO search(kind, source, content) VALUES (?, ?, ?)",
                        ("file", item.get("logical_path", ""), json.dumps(item, ensure_ascii=False)),
                    )
                for item in payload.get("artifacts", []):
                    connection.execute(
                        "INSERT INTO search(kind, source, content) VALUES (?, ?, ?)",
                        (item.get("artifact_type", "artifact"), item.get("source_database", ""), json.dumps(item.get("record", {}), ensure_ascii=False)),
                    )
            partial.replace(path)
        except sqlite3.DatabaseError as error:
            partial.unlink(missing_ok=True)
            LOGGER.warning("No se pudo crear índice FTS5: %s", error)

    @staticmethod
    def _html_report(payload: Mapping[str, Any], custody: Mapping[str, Any]) -> str:
        device = payload.get("device", {})
        case = payload.get("case", {})
        profile = payload.get("case_profile", {})
        methodology = payload.get("methodology", {})
        classification = payload.get("evidence_classification", {})
        rows = "".join(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>".format(
                html.escape(str(item.get("logical_path", ""))),
                html.escape(str(item.get("size", 0))),
                html.escape(str(item.get("sha256", ""))),
                "Copia residual lógica" if item.get("is_recovered") else "Archivo lógico activo",
            )
            for item in payload.get("manifest", [])
        )
        return f"""<!doctype html><html lang='es'><head><meta charset='utf-8'>
        <title>Forensic Mobile Lab Report</title><style>
        body{{font:14px -apple-system,sans-serif;margin:38px;color:#142127}}h1{{color:#087b78}}
        .summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}.box{{padding:14px;background:#edf6f4;border-radius:10px}}
        table{{width:100%;border-collapse:collapse;margin-top:22px}}th,td{{padding:8px;border-bottom:1px solid #ccd9d7;text-align:left}}code{{font-size:10px;word-break:break-all}}
        @media print{{body{{margin:18mm}}.box{{break-inside:avoid}}table{{font-size:10px}}}}
        </style></head><body><h1>Forensic Mobile Lab</h1><p>Informe técnico de adquisición lógica autorizada</p>
        <section class='summary'><div class='box'><b>Caso</b><br>{html.escape(str(profile.get('case_number',case.get('acquisition_id','—'))))}</div>
        <div class='box'><b>Dispositivo</b><br>{html.escape(str(device.get('manufacturer','')))} {html.escape(str(device.get('model','')))}</div>
        <div class='box'><b>Evidencia</b><br>{len(payload.get('manifest', []))} archivos</div></section>
        <h2>Autoridad y examinador</h2><p><b>Examinador:</b> {html.escape(str(profile.get('examiner','—')))} · ID: {html.escape(str(profile.get('examiner_id','—')))} · Organización: {html.escape(str(profile.get('organization','—')))}</p>
        <p><b>Autoridad:</b> {html.escape(str(profile.get('legal_authority','—')))}<br><b>Alcance:</b> {html.escape(str(profile.get('authorized_scope','—')))}</p>
        <h2>Metodología y limitaciones</h2><p>{html.escape(str(methodology.get('scope','')))}</p><p><b>No incluido:</b> {html.escape(str(methodology.get('excluded','')))}</p>
        <p><b>Clasificación:</b> activos {classification.get('ACTIVE_LOGICAL_FILE',0)} · residuales lógicos {classification.get('LOGICAL_RESIDUAL_COPY',0)} · borrados confirmados {classification.get('CONFIRMED_DELETED',0)}.</p>
        <h2>Referencia temporal</h2><p>Mac UTC: {html.escape(str(profile.get('mac_time_utc','—')))} · Zona Mac: {html.escape(str(profile.get('mac_timezone','—')))} · Dispositivo: {html.escape(str(profile.get('device_time','—')))} · Zona dispositivo: {html.escape(str(profile.get('device_timezone','—')))}</p>
        <h2>Integridad</h2><p>Reporte SHA-256: <code>{html.escape(str(custody.get('report_sha256','')))}</code></p>
        <h2>Manifiesto</h2><table><thead><tr><th>Ruta</th><th>Bytes</th><th>SHA-256</th><th>Estado</th></tr></thead><tbody>{rows}</tbody></table>
        <p><small>Las limitaciones y advertencias constan en forensic_report.json.</small></p></body></html>"""

    @staticmethod
    def _build_file_tree(
        manifest: Sequence[FileManifestEntry],
    ) -> Mapping[str, Any]:
        root: dict[str, Any] = {}
        for entry in manifest:
            node = root
            for component in Path(entry.logical_path.lstrip("/")).parts[:-1]:
                node = node.setdefault(component, {})
            filename = Path(entry.logical_path).name
            node.setdefault("_files", []).append(
                {
                    "name": filename,
                    "size": entry.size,
                    "sha256": entry.sha256,
                    "is_recovered": entry.is_recovered,
                }
            )
        return root

    @staticmethod
    def _build_timeline(
        manifest: Sequence[FileManifestEntry],
        artifacts: Sequence[ParsedArtifact],
    ) -> list[Mapping[str, Any]]:
        events: list[Mapping[str, Any]] = []
        for entry in manifest:
            if entry.captured_at:
                events.append(
                    {
                        "timestamp": entry.captured_at,
                        "timestamp_source": "EXIF",
                        "type": "PHOTO_CAPTURED",
                        "description": Path(entry.logical_path).name,
                        "sha256": entry.sha256,
                    }
                )
            events.append(
                {
                    "timestamp": entry.acquired_at,
                    "timestamp_source": "ACQUISITION_CLOCK",
                    "type": "RECOVERED_PHOTO"
                    if entry.is_recovered
                    else "FILE_ACQUIRED",
                    "description": Path(entry.logical_path).name,
                    "sha256": entry.sha256,
                }
            )
        for index, artifact in enumerate(artifacts):
            timestamp = next(
                (
                    value
                    for key, value in artifact.record.items()
                    if any(marker in key for marker in ("timestamp", "date", "time"))
                    and isinstance(value, str)
                ),
                None,
            )
            if timestamp:
                events.append(
                    {
                        "timestamp": timestamp,
                        "timestamp_source": "SQL_RECORD",
                        "type": artifact.artifact_type.value.upper(),
                        "description": f"{artifact.source_table} record {index}",
                        "source_database": artifact.source_database,
                    }
                )
        return sorted(events, key=lambda event: str(event["timestamp"]))

    @staticmethod
    def _build_smart_links(
        artifacts: Sequence[ParsedArtifact],
        manifest: Sequence[FileManifestEntry],
    ) -> list[Mapping[str, Any]]:
        recovered = [entry for entry in manifest if entry.is_recovered]
        links: list[Mapping[str, Any]] = []
        for index, artifact in enumerate(artifacts):
            text = json.dumps(artifact.record, ensure_ascii=False, default=str).lower()
            for entry in recovered:
                filename = Path(entry.logical_path).name
                if filename and filename.lower() in text:
                    links.append(
                        {
                            "artifact_index": index,
                            "artifact_type": artifact.artifact_type.value,
                            "message_source": artifact.source_database,
                            "recovered_file": entry.logical_path,
                            "file_hash": entry.sha256,
                            "link_type": "EXPLICIT_FILENAME_REFERENCE",
                            "status": "VERIFIED_TEXT_MATCH",
                        }
                    )
        return links

    @staticmethod
    def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_suffix(".partial")
        if path.is_symlink() or partial.is_symlink():
            raise DevicePermissionError("La salida del reporte no puede ser un enlace simbólico")
        partial.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        os.chmod(partial, 0o600)
        partial.replace(path)

    @staticmethod
    def _artifacts_csv(path: Path, artifacts: Sequence[ParsedArtifact]) -> None:
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=("artifact_type", "source_database", "source_table", "record_json"),
            )
            writer.writeheader()
            for item in artifacts:
                writer.writerow(
                    {
                        "artifact_type": item.artifact_type.value,
                        "source_database": item.source_database,
                        "source_table": item.source_table,
                        "record_json": json.dumps(item.record, ensure_ascii=False),
                    }
                )

    @staticmethod
    def _manifest_csv(path: Path, manifest: Sequence[FileManifestEntry]) -> None:
        fieldnames = tuple(FileManifestEntry.__dataclass_fields__)
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            for item in manifest:
                writer.writerow(asdict(item))


class CellebriteCloneCore:
    """Orquestador para adquisición autorizada sobre el simulador incluido."""

    def __init__(
        self,
        transport: MobileTransport,
        case_dir: Path,
        categories: Sequence[str] | None = None,
    ) -> None:
        if case_dir.is_symlink():
            raise DevicePermissionError("El expediente no puede ser un enlace simbólico")
        self._case_dir = case_dir.resolve()
        for child in (self._case_dir / "evidence", self._case_dir / "reports"):
            if child.is_symlink():
                raise DevicePermissionError("Las carpetas internas del expediente no pueden ser enlaces simbólicos")
        self._device = DeviceHandler(transport)
        if isinstance(transport, RealADBTransport) and categories:
            category_roots: Mapping[str, tuple[str, ...]] = {
                "photos_media": ("/sdcard/DCIM", "/sdcard/Pictures"),
                "communications": (
                    "/sdcard/Android/data/com.whatsapp/databases",
                    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
                    "/sdcard/WhatsApp/Databases",
                ),
                "documents": ("/sdcard/Download",),
                "logical_recovery": (
                    "/sdcard/.thumbnails",
                    "/sdcard/DCIM/.thumbnails",
                    "/sdcard/Pictures/.thumbnails",
                    "/sdcard/Android/data/com.whatsapp/cache",
                    "/sdcard/Android/data/com.whatsapp/files/.cache",
                    "/sdcard/WhatsApp/Media/.Trash",
                    "/data/system/media/thumbnails",
                ),
                "file_tree": (),
            }
            roots = tuple(dict.fromkeys(
                root for category in categories
                for root in category_roots.get(category, ())
            ))
        else:
            roots = (
                FileExtractor.ADB_PUBLIC_ROOTS
                if isinstance(transport, RealADBTransport)
                else FileExtractor.CRITICAL_ROOTS
            )
        self._extractor = FileExtractor(
            self._device, self._case_dir / "evidence", roots
        )
        self._parser = DatabaseParser()
        self._reporter = ForensicReporter(self._case_dir / "reports")

    def run(self) -> Mapping[str, Path]:
        try:
            identity = self._device.connect()
            result = AcquisitionResult(
                acquisition_id=str(uuid.uuid4()),
                device=identity,
                started_at=_utc_now(),
            )
            manifest, warnings = self._extractor.extract()
            result.manifest.extend(manifest)
            result.warnings.extend(warnings)
            artifacts, warnings = self._parser.parse(manifest)
            result.artifacts.extend(artifacts)
            result.warnings.extend(warnings)
            result.completed_at = _utc_now()
            return self._reporter.generate(result)
        finally:
            self._device.disconnect()


def create_demo_device(root: Path) -> None:
    if root.exists():
        shutil.rmtree(root)
    sms_dir = root / "data/data/com.android.providers.telephony/databases"
    whatsapp_dir = root / "data/data/com.whatsapp/databases"
    calls_dir = root / "data/data/com.android.providers.contacts/databases"
    for directory in (sms_dir, whatsapp_dir, calls_dir):
        directory.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(sms_dir / "mmssms.db") as connection:
        connection.execute(
            "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, body TEXT, date INTEGER)"
        )
        connection.executemany(
            "INSERT INTO sms(address, body, date) VALUES (?, ?, ?)",
            (
                ("+15550000001", "Mensaje de laboratorio", 1710000000000),
                ("+15550000002", "Prueba de integridad", 1710000060000),
            ),
        )
    with sqlite3.connect(whatsapp_dir / "msgstore.db") as connection:
        connection.execute(
            "CREATE TABLE message (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, data TEXT, timestamp INTEGER)"
        )
        connection.execute(
            "INSERT INTO message(key_remote_jid, data, timestamp) VALUES (?, ?, ?)",
            ("15550000003@s.whatsapp.net", "Chat simulado", 1710000120000),
        )
    with sqlite3.connect(calls_dir / "calls.db") as connection:
        connection.execute(
            "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER)"
        )
        connection.execute(
            "INSERT INTO calls(number, date, duration) VALUES (?, ?, ?)",
            ("+15550000004", 1710000180000, 83),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _termination_signal(signum: int, frame: Any) -> None:
    del signum, frame
    raise KeyboardInterrupt("Adquisición cancelada por el operador")


def audit_sqlite_database(database: Path, output: Path) -> Mapping[str, Any]:
    if output.is_symlink():
        raise DevicePermissionError("La salida del reporte no puede ser un enlace simbólico")
    if database.is_symlink():
        raise DevicePermissionError("No se aceptan enlaces simbólicos como evidencia SQLite")
    database = database.resolve(strict=True)
    tables: list[dict[str, Any]] = []
    uri = f"{database.as_uri()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=15.0) as connection:
            integrity_row = connection.execute("PRAGMA integrity_check").fetchone()
            table_names = [
                str(row[0]) for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ]
            for table in table_names:
                quoted = '"' + table.replace('"', '""') + '"'
                columns = [
                    {"name": row[1], "type": row[2], "not_null": bool(row[3]), "primary_key": bool(row[5])}
                    for row in connection.execute(f"PRAGMA table_info({quoted})")
                ]
                try:
                    count = int(connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0])
                except sqlite3.DatabaseError:
                    count = -1
                tables.append({"name": table, "row_count": count, "columns": columns})
    except sqlite3.DatabaseError as error:
        raise CorruptDataError(f"No se pudo auditar SQLite: {error}") from error

    sidecars: list[dict[str, Any]] = []
    candidate_strings: list[dict[str, Any]] = []
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(database) + suffix)
        if not sidecar.is_file() or sidecar.is_symlink():
            continue
        data = sidecar.read_bytes()
        sidecars.append({
            "path": str(sidecar), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
        })
        for match in re.finditer(rb"[\x20-\x7e]{8,}", data):
            candidate_strings.append({
                "sidecar": str(sidecar), "offset": match.start(),
                "text": match.group(0)[:500].decode("utf-8", errors="replace"),
                "classification": "UNVERIFIED_PRINTABLE_SEQUENCE",
            })
            if len(candidate_strings) >= 500:
                break
    report = {
        "status": "success", "tool": "sqlite_wal_audit", "created_at_utc": _utc_now(),
        "database": str(database), "database_sha256": DeviceHandler._sha256_file(database),
        "database_size": database.stat().st_size,
        "integrity": integrity_row[0] if integrity_row else "unknown",
        "tables": tables, "sidecars": sidecars,
        "candidate_strings": candidate_strings,
        "limitations": "Las cadenas de WAL/journal son indicios no verificados; no se etiquetan como filas recuperadas sin reconstrucción de página.",
    }
    ForensicReporter._atomic_json(output.resolve(), report)
    return report


def audit_apk(apk: Path, output: Path) -> Mapping[str, Any]:
    if output.is_symlink():
        raise DevicePermissionError("La salida del reporte no puede ser un enlace simbólico")
    if apk.is_symlink():
        raise CorruptDataError("El archivo APK no puede ser un enlace simbólico")
    apk = apk.resolve(strict=True)
    if not zipfile.is_zipfile(apk):
        raise CorruptDataError("El archivo no es un APK/ZIP válido")
    entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            entries.append({
                "name": info.filename, "compressed_size": info.compress_size,
                "size": info.file_size, "crc32": f"{info.CRC:08x}",
                "encrypted": bool(info.flag_bits & 0x1),
            })
    names = [item["name"] for item in entries]
    report = {
        "status": "success", "tool": "apk_audit", "created_at_utc": _utc_now(),
        "apk": str(apk), "size": apk.stat().st_size,
        "sha256": DeviceHandler._sha256_file(apk),
        "entries_count": len(entries), "has_manifest": "AndroidManifest.xml" in names,
        "dex_files": sorted(name for name in names if re.fullmatch(r"classes\d*\.dex", Path(name).name)),
        "native_libraries": sorted(name for name in names if name.startswith("lib/") and name.endswith(".so")),
        "signing_files": sorted(name for name in names if name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))),
        "entries": entries,
        "limitations": "Inventario estático; AndroidManifest.xml binario no se interpreta sin un decodificador AXML dedicado.",
    }
    ForensicReporter._atomic_json(output.resolve(), report)
    return report


def analyze_chrome_history(database: Path, output: Path) -> Mapping[str, Any]:
    if output.is_symlink():
        raise DevicePermissionError("La salida del reporte no puede ser un enlace simbólico")
    if database.is_symlink():
        raise DevicePermissionError("No se aceptan enlaces simbólicos como historial Chrome")
    database = database.resolve(strict=True)

    def chrome_time(value: Any) -> str | None:
        try:
            numeric = int(value)
            if numeric <= 0:
                return None
            return datetime.fromtimestamp(
                numeric / 1_000_000 - 11_644_473_600, tz=timezone.utc
            ).isoformat()
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    uri = f"{database.as_uri()}?mode=ro"
    visits: list[dict[str, Any]] = []
    downloads: list[dict[str, Any]] = []
    searches: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        with sqlite3.connect(uri, uri=True, timeout=15.0) as connection:
            connection.row_factory = sqlite3.Row
            tables = {
                str(row[0]) for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if {"urls", "visits"}.issubset(tables):
                for row in connection.execute(
                    "SELECT v.id, v.visit_time, v.from_visit, v.transition, "
                    "v.visit_duration, u.url, u.title, u.visit_count, u.typed_count "
                    "FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time"
                ):
                    item = dict(row)
                    item["visit_time_utc"] = chrome_time(item.get("visit_time"))
                    visits.append(item)
            else:
                warnings.append("No se encontraron las tablas urls/visits de Chrome")
            if "keyword_search_terms" in tables and "urls" in tables:
                for row in connection.execute(
                    "SELECT k.term, k.normalized_term, u.url, u.title "
                    "FROM keyword_search_terms k LEFT JOIN urls u ON u.id=k.url_id"
                ):
                    searches.append(dict(row))
            if "downloads" in tables:
                columns = {
                    str(row[1]) for row in connection.execute("PRAGMA table_info(downloads)")
                }
                wanted = [
                    name for name in (
                        "id", "current_path", "target_path", "tab_url", "tab_referrer_url",
                        "site_url", "referrer", "mime_type", "original_mime_type", "start_time",
                        "end_time", "received_bytes", "total_bytes", "state", "danger_type",
                    ) if name in columns
                ]
                query = "SELECT " + ", ".join('"' + name + '"' for name in wanted) + " FROM downloads"
                for row in connection.execute(query):
                    item = dict(row)
                    for field_name in ("start_time", "end_time"):
                        if field_name in item:
                            item[f"{field_name}_utc"] = chrome_time(item[field_name])
                    downloads.append(item)
    except sqlite3.DatabaseError as error:
        raise CorruptDataError(f"Historial Chrome inválido o corrupto: {error}") from error

    sidecars: list[dict[str, Any]] = []
    for suffix in ("-wal", "-shm", "-journal"):
        candidate = Path(str(database) + suffix)
        if candidate.is_file() and not candidate.is_symlink():
            sidecars.append({
                "path": str(candidate), "size": candidate.stat().st_size,
                "sha256": DeviceHandler._sha256_file(candidate),
            })
    report = {
        "status": "success", "tool": "chrome_history", "created_at_utc": _utc_now(),
        "source": str(database), "source_sha256": DeviceHandler._sha256_file(database),
        "source_size": database.stat().st_size,
        "integrity": integrity[0] if integrity else "unknown",
        "visits_count": len(visits), "searches_count": len(searches),
        "downloads_count": len(downloads), "visits": visits,
        "searches": searches, "downloads": downloads, "sidecars": sidecars,
        "warnings": warnings,
        "limitations": (
            "Analiza la base History suministrada. No sincroniza la cuenta Google ni "
            "accede al sandbox privado de Chrome sin permisos del sistema."
        ),
    }
    ForensicReporter._atomic_json(output.resolve(), report)
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Laboratorio de adquisición forense móvil simulada"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="Crear un dispositivo demo y analizarlo")
    demo.add_argument("--workspace", type=Path, default=Path("demo_run"))
    acquire = subparsers.add_parser("acquire", help="Analizar una carpeta de dispositivo simulado")
    acquire.add_argument("device_root", type=Path)
    acquire.add_argument("case_dir", type=Path)
    acquire.add_argument("--locked", action="store_true")
    acquire.add_argument("--unauthorized", action="store_true")
    adb = subparsers.add_parser(
        "adb", help="Adquirir archivos públicos de un Android ADB autorizado"
    )
    adb.add_argument("case_dir", type=Path)
    adb.add_argument("--serial")
    adb.add_argument("--adb-path")
    adb.add_argument(
        "--categories",
        nargs="+",
        choices=("photos_media", "communications", "documents", "logical_recovery", "file_tree"),
    )
    probe = subparsers.add_parser(
        "probe", help="Comprobar identidad y estado de un Android ADB autorizado"
    )
    probe.add_argument("--serial")
    probe.add_argument("--adb-path")
    verify = subparsers.add_parser(
        "verify", help="Recalcular hashes y verificar un expediente existente"
    )
    verify.add_argument("report", type=Path)
    search = subparsers.add_parser("search", help="Consultar el índice FTS5 de un caso")
    search.add_argument("index", type=Path)
    search.add_argument("query")
    redact = subparsers.add_parser(
        "redact", help="Crear una copia redactada sin modificar el reporte original"
    )
    redact.add_argument("report", type=Path)
    redact.add_argument("output", type=Path)
    seal = subparsers.add_parser("seal", help="Actualizar el manifiesto maestro del caso")
    seal.add_argument("case_root", type=Path)
    whatsapp_scan = subparsers.add_parser(
        "whatsapp-auto-scan",
        help="Buscar y guardar automáticamente un backup msgstore.db.crypt14",
    )
    whatsapp_scan.add_argument(
        "--output", type=Path, default=Path.cwd() / "msgstore.db.crypt14"
    )
    whatsapp_scan.add_argument(
        "--key-output", type=Path, default=Path.cwd() / "whatsapp.key"
    )
    whatsapp_scan.add_argument("--serial")
    whatsapp_scan.add_argument("--adb-path")
    whatsapp_decrypt = subparsers.add_parser(
        "whatsapp-decrypt",
        help="Descifrar Crypt14 con una clave aportada y validar la SQLite resultante",
    )
    whatsapp_decrypt.add_argument("encrypted", type=Path)
    whatsapp_decrypt.add_argument("key", type=Path)
    whatsapp_decrypt.add_argument("output", type=Path)
    carve = subparsers.add_parser(
        "carve-adb", help="Buscar imágenes embebidas en archivos públicos accesibles por ADB"
    )
    carve.add_argument("output_dir", type=Path)
    carve.add_argument("--serial")
    carve.add_argument("--adb-path")
    sqlite_audit = subparsers.add_parser(
        "sqlite-audit", help="Auditar SQLite y sus sidecars WAL/SHM/journal"
    )
    sqlite_audit.add_argument("database", type=Path)
    sqlite_audit.add_argument("output", type=Path)
    apk_audit = subparsers.add_parser("apk-audit", help="Inventariar contenido de un APK")
    apk_audit.add_argument("apk", type=Path)
    apk_audit.add_argument("output", type=Path)
    inventory = subparsers.add_parser(
        "android-inventory", help="Inventariar aplicaciones visibles mediante ADB"
    )
    inventory.add_argument("output", type=Path)
    inventory.add_argument("--serial")
    inventory.add_argument("--adb-path")
    communications = subparsers.add_parser(
        "android-communications",
        help="Extraer contactos y SMS concedidos al usuario adb shell",
    )
    communications.add_argument("output", type=Path)
    communications.add_argument("--serial")
    communications.add_argument("--adb-path")
    chrome = subparsers.add_parser(
        "chrome-history", help="Analizar una base History de Google Chrome"
    )
    chrome.add_argument("database", type=Path)
    chrome.add_argument("output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    signal.signal(signal.SIGTERM, _termination_signal)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "sqlite-audit":
            print(json.dumps(audit_sqlite_database(args.database, args.output), ensure_ascii=False, indent=2))
            return 0
        if args.command == "apk-audit":
            print(json.dumps(audit_apk(args.apk, args.output), ensure_ascii=False, indent=2))
            return 0
        if args.command == "chrome-history":
            print(json.dumps(
                analyze_chrome_history(args.database, args.output),
                ensure_ascii=False, indent=2,
            ))
            return 0
        if args.command == "android-inventory":
            if args.output.is_symlink():
                raise DevicePermissionError("La salida no puede ser un enlace simbólico")
            inventory_transport = RealADBTransport(serial=args.serial, adb_path=args.adb_path)
            try:
                inventory_transport.connect(10.0)
                result = inventory_transport.application_inventory()
                ForensicReporter._atomic_json(args.output.resolve(), result)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            finally:
                inventory_transport.disconnect()
        if args.command == "android-communications":
            if args.output.is_symlink():
                raise DevicePermissionError("La salida no puede ser un enlace simbólico")
            communications_transport = RealADBTransport(
                serial=args.serial, adb_path=args.adb_path
            )
            try:
                communications_transport.connect(10.0)
                result = dict(communications_transport.extract_public_communications())
                canonical_records = json.dumps(
                    {"contacts": result["contacts"], "sms": result["sms"]},
                    ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                ).encode("utf-8")
                result["records_sha256"] = hashlib.sha256(canonical_records).hexdigest()
                output = args.output.resolve()
                ForensicReporter._atomic_json(output, result)
                report_sha256 = DeviceHandler._sha256_file(output)
                output.with_suffix(output.suffix + ".sha256").write_text(
                    f"{report_sha256}  {output.name}\n", encoding="utf-8"
                )
                print(json.dumps({
                    **result, "report_path": str(output),
                    "report_sha256": report_sha256,
                }, ensure_ascii=False, indent=2))
                return 0
            finally:
                communications_transport.disconnect()
        if args.command == "carve-adb":
            carve_transport = RealADBTransport(
                serial=args.serial, adb_path=args.adb_path
            )
            try:
                carve_transport.connect(10.0)
                report = ADBFileCarvingEngine(
                    carve_transport, args.output_dir
                ).run()
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0
            finally:
                carve_transport.disconnect()
        if args.command == "whatsapp-decrypt":
            if args.encrypted.is_symlink() or args.key.is_symlink() or args.output.is_symlink():
                raise DevicePermissionError("No se aceptan enlaces simbólicos para Crypt14, la clave o la salida")
            encrypted = args.encrypted.resolve(strict=True)
            key_file = args.key.resolve(strict=True)
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            partial = output.with_suffix(output.suffix + ".partial")
            partial.unlink(missing_ok=True)
            environment = os.environ.copy()
            bundled_path = str(_BUNDLED_PACKAGES)
            environment["PYTHONPATH"] = bundled_path + os.pathsep + environment.get("PYTHONPATH", "")
            command = [
                sys.executable,
                "-m",
                "wa_crypt_tools.wadecrypt",
                "-nm",
                str(key_file),
                str(encrypted),
                str(partial),
            ]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1800.0,
                check=False,
                env=environment,
            )
            if result.returncode != 0 or not partial.is_file():
                partial.unlink(missing_ok=True)
                raise AcquisitionError(
                    "Crypt14 no pudo descifrarse; comprueba que la clave corresponda al backup. "
                    + (result.stderr.strip() or result.stdout.strip())
                )
            with partial.open("rb") as stream:
                header = stream.read(16)
            if header != b"SQLite format 3\x00":
                partial.unlink(missing_ok=True)
                raise CorruptDataError(
                    "La salida no tiene una cabecera SQLite válida; la clave no corresponde al backup"
                )
            try:
                uri = f"{partial.as_uri()}?mode=ro"
                with sqlite3.connect(uri, uri=True, timeout=10.0) as connection:
                    integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise CorruptDataError("La SQLite descifrada no superó integrity_check")
            except sqlite3.DatabaseError as error:
                partial.unlink(missing_ok=True)
                raise CorruptDataError(f"SQLite descifrada corrupta: {error}") from error
            partial.replace(output)
            os.chmod(output, 0o600)
            encrypted_hash = DeviceHandler._sha256_file(encrypted)
            decrypted_hash = DeviceHandler._sha256_file(output)
            parsed_entry = FileManifestEntry(
                logical_path="whatsapp/msgstore.db",
                evidence_path=str(output),
                size=output.stat().st_size,
                sha256=decrypted_hash,
                crc32="not-applicable",
                acquired_at=_utc_now(),
            )
            artifacts, parser_warnings = DatabaseParser().parse([parsed_entry])
            analysis_path = output.with_name("whatsapp_analysis.json")
            ForensicReporter._atomic_json(analysis_path, {
                "source_encrypted": str(encrypted),
                "source_encrypted_sha256": encrypted_hash,
                "decrypted_database": str(output),
                "decrypted_sha256": decrypted_hash,
                "records_count": len(artifacts),
                "warnings": parser_warnings,
                "artifacts": [
                    {
                        "artifact_type": artifact.artifact_type.value,
                        "source_table": artifact.source_table,
                        "record": artifact.record,
                    }
                    for artifact in artifacts
                ],
            })
            print(json.dumps({
                "status": "success",
                "encrypted_path": str(encrypted),
                "key_path": str(key_file),
                "decrypted_path": str(output),
                "encrypted_sha256": encrypted_hash,
                "decrypted_sha256": decrypted_hash,
                "size": output.stat().st_size,
                "sqlite_integrity": "ok",
                "analysis_path": str(analysis_path),
                "records_count": len(artifacts),
                "parser_warnings": parser_warnings,
            }, ensure_ascii=False, indent=2))
            return 0
        if args.command == "whatsapp-auto-scan":
            scan_transport = RealADBTransport(
                serial=args.serial, adb_path=args.adb_path
            )
            try:
                scan_transport.connect(10.0)
                pair = scan_transport.find_whatsapp_pair()
                if pair is None:
                    raise AcquisitionError(
                        "No se encontró ningún archivo .db.crypt14 accesible mediante ADB"
                    )
                result = scan_transport.copy_whatsapp_crypt14(
                    str(pair["backup"]), args.output
                )
                key_result: Mapping[str, Any] | None = None
                if pair.get("key"):
                    key_result = scan_transport.copy_public_whatsapp_key(
                        str(pair["key"]), args.key_output
                    )
                print(json.dumps({
                    "status": "success",
                    "matches_found": pair["backups_found"],
                    "backup_mtime": pair["backup_mtime"],
                    "key_found": key_result is not None,
                    "key": key_result,
                    **result,
                }, ensure_ascii=False, indent=2))
                return 0
            finally:
                scan_transport.disconnect()
        if args.command == "seal":
            if args.case_root.is_symlink():
                raise DevicePermissionError("El expediente no puede ser un enlace simbólico")
            case_root = args.case_root.resolve()
            output = case_root / "reports/case_master_manifest.json"
            ForensicReporter._write_master_manifest(output, case_root)
            print(json.dumps({"status": "sealed", "manifest": str(output)}, indent=2))
            return 0
        if args.command == "redact":
            if args.report.is_symlink() or args.output.is_symlink():
                raise DevicePermissionError("El reporte y la salida deben ser archivos regulares, no enlaces simbólicos")
            source = json.loads(args.report.resolve().read_text(encoding="utf-8"))
            sensitive_keys = {"latitude", "longitude", "gps_raw", "address", "number", "phone"}
            def sanitize(value: Any, key: str = "") -> Any:
                if key.lower() in sensitive_keys:
                    return "[REDACTED]"
                if isinstance(value, dict):
                    return {name: sanitize(item, str(name)) for name, item in value.items()}
                if isinstance(value, list):
                    return [sanitize(item) for item in value]
                if isinstance(value, str):
                    return re.sub(r"(?<!\w)\+?\d[\d\s().-]{6,}\d(?!\w)", "[REDACTED PHONE]", value)
                return value
            redacted = sanitize(source)
            redacted["redaction"] = {
                "created_at_utc": _utc_now(),
                "source_report_sha256": hashlib.sha256(args.report.resolve().read_bytes()).hexdigest(),
                "policy": "PHONE_AND_GPS",
                "original_evidence_modified": False,
            }
            ForensicReporter._atomic_json(args.output.resolve(), redacted)
            print(json.dumps({"output": str(args.output.resolve()), "status": "redacted_copy_created"}, indent=2))
            return 0
        if args.command == "search":
            if args.index.is_symlink():
                raise DevicePermissionError("El índice no puede ser un enlace simbólico")
            index = args.index.resolve(strict=True)
            with sqlite3.connect(f"{index.as_uri()}?mode=ro&immutable=1", uri=True) as connection:
                rows = connection.execute(
                    "SELECT kind, source, snippet(search, 2, '[', ']', '…', 24) "
                    "FROM search WHERE search MATCH ? LIMIT 250",
                    (args.query,),
                ).fetchall()
            print(json.dumps([
                {"kind": row[0], "source": row[1], "snippet": row[2]}
                for row in rows
            ], ensure_ascii=False, indent=2))
            return 0
        if args.command == "verify":
            report_path = args.report.resolve()
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            checks: list[dict[str, Any]] = []
            case_root = report_path.parent.parent.resolve()
            for item in payload.get("manifest", []):
                relative_value = item.get("case_relative_path")
                evidence = Path(str(item.get("evidence_path", "")))
                if isinstance(relative_value, str) and relative_value:
                    relative = Path(relative_value)
                    if relative.is_absolute() or ".." in relative.parts:
                        evidence = Path("")
                    else:
                        evidence = case_root / relative
                safe = False
                try:
                    safe = evidence.is_file() and not evidence.is_symlink()
                    evidence.resolve(strict=True).relative_to(case_root)
                except (OSError, ValueError):
                    safe = False
                actual = DeviceHandler._sha256_file(evidence) if safe else None
                checks.append({
                    "path": str(evidence),
                    "exists": evidence.is_file(),
                    "safe_case_path": safe,
                    "expected_sha256": item.get("sha256"),
                    "actual_sha256": actual,
                    "valid": safe and actual == item.get("sha256"),
                })
            master_path = report_path.parent / "case_master_manifest.json"
            master_checks: list[dict[str, Any]] = []
            declared_paths: set[str] = set()
            if master_path.is_file():
                master = json.loads(master_path.read_text(encoding="utf-8"))
                for item in master.get("files", []):
                    relative = str(item.get("path", ""))
                    declared_paths.add(relative)
                    candidate = case_root / relative
                    safe = False
                    try:
                        safe = candidate.is_file() and not candidate.is_symlink()
                        candidate.resolve(strict=True).relative_to(case_root)
                    except (OSError, ValueError):
                        safe = False
                    actual = DeviceHandler._sha256_file(candidate) if safe else None
                    master_checks.append({
                        "path": relative,
                        "expected_sha256": item.get("sha256"),
                        "actual_sha256": actual,
                        "expected_size": item.get("size"),
                        "actual_size": candidate.stat().st_size if safe else None,
                        "valid": safe and actual == item.get("sha256")
                        and candidate.stat().st_size == item.get("size"),
                    })
            actual_paths = {
                candidate.relative_to(case_root).as_posix()
                for candidate in case_root.rglob("*")
                if candidate.is_file()
                and candidate != master_path
                and ".ui_cache" not in candidate.relative_to(case_root).parts
                and candidate.suffix != ".partial"
                and candidate.name != "integrity_verification.json"
                and candidate.name != "case_signature.json"
            }
            undeclared = sorted(actual_paths - declared_paths)
            missing = sorted(declared_paths - actual_paths)
            master_valid = (
                master_path.is_file()
                and all(item["valid"] for item in master_checks)
                and not undeclared
                and not missing
            )
            chain_checks = [
                _verify_hash_chain(report_path.parent / "chain_of_custody.json", "events", "custody"),
                _verify_hash_chain(report_path.parent / "examiner_annotations.json", "annotations", "annotation"),
                _verify_hash_chain(report_path.parent / "application_audit.json", "events", "application"),
            ]
            chains_valid = all(item["valid"] for item in chain_checks)
            verification = {
                "verified_at_utc": _utc_now(),
                "report": str(report_path),
                "files_checked": len(checks),
                "valid_files": sum(check["valid"] for check in checks),
                "master_manifest_valid": master_valid,
                "undeclared_files": undeclared,
                "missing_declared_files": missing,
                "hash_chains_valid": chains_valid,
                "hash_chain_checks": chain_checks,
                "master_checks": master_checks,
                "all_valid": all(check["valid"] for check in checks) and master_valid and chains_valid,
                "checks": checks,
            }
            output = report_path.parent / "integrity_verification.json"
            ForensicReporter._atomic_json(output, verification)
            print(json.dumps(verification, indent=2))
            return 0 if verification["all_valid"] else 4
        if args.command == "probe":
            probe_transport = RealADBTransport(
                serial=args.serial, adb_path=args.adb_path
            )
            try:
                probe_transport.connect(10.0)
                print(json.dumps(probe_transport.diagnostics(), indent=2))
                return 0
            finally:
                probe_transport.disconnect()
        if args.command == "demo":
            device_root = args.workspace / "simulated_device"
            case_dir = args.workspace / "case"
            create_demo_device(device_root)
            transport: MobileTransport = SimulatedMobileTransport(device_root)
        elif args.command == "acquire":
            device_root = args.device_root
            case_dir = args.case_dir
            transport = SimulatedMobileTransport(
                device_root, locked=args.locked, authorized=not args.unauthorized
            )
        else:
            case_dir = args.case_dir
            transport = RealADBTransport(
                serial=args.serial, adb_path=args.adb_path
            )
        reports = CellebriteCloneCore(
            transport,
            case_dir,
            categories=getattr(args, "categories", None),
        ).run()
    except AcquisitionError as error:
        LOGGER.error("Adquisición fallida: %s", error)
        return 2
    except (OSError, sqlite3.DatabaseError) as error:
        LOGGER.error("Fallo local: %s", error)
        return 3
    except KeyboardInterrupt:
        LOGGER.warning("Adquisición cancelada; procesos ADB cerrados y parciales descartados")
        return 130
    print(json.dumps({key: str(value) for key, value in reports.items()}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
