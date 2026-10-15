from __future__ import annotations

import hashlib
import json
import os
import queue
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import zlib
from io import BytesIO
from dataclasses import dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, VERTICAL, X, Y, filedialog, messagebox
import tkinter as tk
from tkinter import ttk
from typing import Callable, Final, Iterator, Sequence

try:
    from PIL import Image, ImageTk
except ImportError:  # La extracción continúa; solo se desactiva la vista previa.
    Image = None  # type: ignore[assignment]
    ImageTk = None  # type: ignore[assignment]


SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
LOCAL_BACKUP: Final[Path] = SCRIPT_DIR / "msgstore.db.crypt14"
LOCAL_KEY: Final[Path] = SCRIPT_DIR / "whatsapp.key"
DECRYPTED_DB: Final[Path] = SCRIPT_DIR / "msgstore.db"
CARVING_OUTPUT: Final[Path] = SCRIPT_DIR / "recuperacion_cellebrite"
PUBLIC_ROOTS: Final[tuple[str, ...]] = ("/sdcard", "/storage/emulated/0")
PUBLIC_KEY_PATHS: Final[tuple[str, ...]] = (
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/key",
    "/sdcard/Android/media/com.whatsapp/files/key",
    "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases/key",
    "/storage/emulated/0/Android/media/com.whatsapp/files/key",
)


class ForensicError(RuntimeError):
    """Fallo controlado de adquisición o análisis."""


@dataclass(frozen=True)
class RemoteBackup:
    path: str
    modified_at: int


@dataclass(frozen=True)
class CopyResult:
    remote_path: str
    local_path: Path
    size: int
    sha256: str
    crc32: str


class ADBClient:
    def __init__(self) -> None:
        bundled = SCRIPT_DIR / "platform-tools" / "adb"
        detected = shutil.which("adb")
        if bundled.is_file() and os.access(bundled, os.X_OK):
            self.adb = str(bundled)
        elif detected:
            self.adb = detected
        else:
            raise ForensicError(
                "ADB no está disponible. Instala Android Platform Tools o coloca "
                "platform-tools junto a app.py."
            )
        self.serial: str | None = None

    def connect(self) -> str:
        completed = self._run(["devices"], use_serial=False)
        devices: list[tuple[str, str]] = []
        for line in completed.stdout.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 2:
                devices.append((fields[0], fields[1]))
        ready = [serial for serial, state in devices if state == "device"]
        if not ready:
            detail = ", ".join(f"{serial}={state}" for serial, state in devices)
            raise ForensicError(
                "No hay un Android ADB autorizado. Desbloquea el teléfono y acepta "
                f"la huella RSA. {detail}"
            )
        if len(ready) > 1:
            raise ForensicError(
                "Hay varios dispositivos conectados. Deja conectado solamente el que analizarás."
            )
        self.serial = ready[0]
        return self.serial

    def scan_backups(self) -> list[RemoteBackup]:
        discovered: dict[str, int] = {}
        for root in PUBLIC_ROOTS:
            command = (
                f"find {shlex.quote(root)} -type f -name '*.db.crypt14' "
                "2>/dev/null"
            )
            completed = self._run(["shell", "sh", "-c", command], check=False, timeout=180)
            if completed.returncode not in (0, 1):
                continue
            for line in completed.stdout.splitlines():
                path = line.strip()
                if self._is_public_path(path) and path.endswith(".db.crypt14"):
                    discovered[path] = self.remote_mtime(path)
        return sorted(
            (RemoteBackup(path, modified) for path, modified in discovered.items()),
            key=lambda item: (item.modified_at, Path(item.path).name == "msgstore.db.crypt14"),
            reverse=True,
        )

    def find_public_key(self, backup_path: str) -> str | None:
        candidates = [str(Path(backup_path).parent / "key"), *PUBLIC_KEY_PATHS]
        for candidate in dict.fromkeys(candidates):
            if not self._is_public_path(candidate):
                continue
            command = f"test -f {shlex.quote(candidate)} && echo FOUND"
            completed = self._run(
                ["shell", "sh", "-c", command], check=False, timeout=15
            )
            if completed.returncode == 0 and completed.stdout.strip() == "FOUND":
                return candidate
        return None

    def remote_mtime(self, path: str) -> int:
        self._require_public_path(path)
        completed = self._run(
            ["shell", "stat", "-c", "%Y", path], check=False, timeout=15
        )
        try:
            return int(completed.stdout.strip()) if completed.returncode == 0 else 0
        except ValueError:
            return 0

    def copy_public_file(self, remote_path: str, destination: Path) -> CopyResult:
        self._require_public_path(remote_path)
        destination = destination.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_suffix(destination.suffix + ".partial")
        partial.unlink(missing_ok=True)
        command = [self.adb]
        if self.serial:
            command.extend(["-s", self.serial])
        command.extend(["exec-out", "sh", "-c", f"cat -- {shlex.quote(remote_path)}"])
        digest = hashlib.sha256()
        crc = 0
        size = 0
        with tempfile.TemporaryFile() as error_stream:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=error_stream,
                start_new_session=True,
            )
            try:
                if process.stdout is None:
                    raise ForensicError("ADB no proporcionó un flujo de lectura")
                with partial.open("wb") as output:
                    while True:
                        chunk = process.stdout.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                        digest.update(chunk)
                        crc = zlib.crc32(chunk, crc)
                        size += len(chunk)
                return_code = process.wait(timeout=30)
                if return_code != 0:
                    error_stream.seek(0)
                    detail = error_stream.read().decode("utf-8", errors="replace")
                    raise ForensicError(f"ADB no pudo copiar {remote_path}: {detail.strip()}")
                partial.replace(destination)
            except BaseException:
                partial.unlink(missing_ok=True)
                if process.poll() is None:
                    process.terminate()
                raise
            finally:
                if process.stdout:
                    process.stdout.close()
        return CopyResult(
            remote_path=remote_path,
            local_path=destination,
            size=size,
            sha256=digest.hexdigest(),
            crc32=f"{crc & 0xFFFFFFFF:08x}",
        )

    def iter_public_files(self) -> Iterator[str]:
        seen: set[str] = set()
        for root in PUBLIC_ROOTS:
            completed = self._run(
                ["shell", "find", root, "-type", "f"], check=False, timeout=300
            )
            for raw_path in completed.stdout.splitlines():
                path = raw_path.strip()
                if self._is_public_path(path) and path not in seen:
                    seen.add(path)
                    yield path

    def read_public_file(self, remote_path: str, maximum_bytes: int) -> bytes:
        self._require_public_path(remote_path)
        command = [self.adb]
        if self.serial:
            command.extend(["-s", self.serial])
        command.extend(["exec-out", "sh", "-c", f"cat -- {shlex.quote(remote_path)}"])
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=180)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.communicate()
            raise ForensicError(f"Tiempo agotado leyendo {remote_path}") from error
        if process.returncode != 0:
            raise PermissionError(stderr.decode("utf-8", errors="replace").strip())
        if len(stdout) > maximum_bytes:
            raise ForensicError(
                f"Archivo omitido por tamaño ({len(stdout)} bytes): {remote_path}"
            )
        return stdout

    def _run(
        self,
        arguments: Sequence[str],
        *,
        use_serial: bool = True,
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.adb]
        if use_serial and self.serial:
            command.extend(["-s", self.serial])
        command.extend(arguments)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ForensicError("El comando ADB agotó el tiempo") from error
        if check and completed.returncode != 0:
            raise ForensicError(completed.stderr.strip() or "ADB devolvió un error")
        return completed

    @staticmethod
    def _is_public_path(path: str) -> bool:
        return (
            "\x00" not in path
            and ".." not in Path(path).parts
            and any(path.startswith(root + "/") for root in PUBLIC_ROOTS)
        )

    def _require_public_path(self, path: str) -> None:
        if not self._is_public_path(path):
            raise ForensicError(f"Ruta fuera del almacenamiento público permitido: {path}")


@dataclass(frozen=True)
class CarvedImage:
    source_path: str
    output_path: Path
    offset: int
    size: int
    kind: str
    sha256: str
    crc32: str


class CellebriteLiteEngine:
    JPEG_START: Final[bytes] = b"\xff\xd8\xff"
    JPEG_END: Final[bytes] = b"\xff\xd9"
    PNG_START: Final[bytes] = b"\x89PNG\r\n\x1a\n"
    PNG_IEND: Final[bytes] = b"IEND"

    def __init__(self, adb: ADBClient, output: Path = CARVING_OUTPUT) -> None:
        self.adb = adb
        self.output = output.resolve()
        self.maximum_source_bytes = 512 * 1024 * 1024

    def scan_device(self, notify: Callable[[str, object], None]) -> list[CarvedImage]:
        self.output.mkdir(parents=True, exist_ok=True)
        results: list[CarvedImage] = []
        recovered_hashes: set[str] = set()
        for index, remote_path in enumerate(self.adb.iter_public_files(), start=1):
            notify("log", f"Escaneando bloque {index}: {remote_path}")
            try:
                payload = self.adb.read_public_file(remote_path, self.maximum_source_bytes)
            except (PermissionError, ForensicError) as error:
                notify("log", f"Omitido: {error}")
                continue
            for offset, data, extension in self._carve(payload):
                digest = hashlib.sha256(data).hexdigest()
                if digest in recovered_hashes:
                    notify("log", f"Duplicado omitido: {remote_path} @ {offset}")
                    continue
                if not self._valid_image(data, extension):
                    notify("log", f"Firma descartada por Pillow: {remote_path} @ {offset}")
                    continue
                destination = self.output / f"carved_{len(results) + 1:06d}_{digest[:12]}.{extension}"
                if not destination.exists():
                    partial = destination.with_suffix(destination.suffix + ".partial")
                    partial.write_bytes(data)
                    partial.replace(destination)
                recovered_hashes.add(digest)
                item = CarvedImage(
                    source_path=remote_path,
                    output_path=destination,
                    offset=offset,
                    size=len(data),
                    kind=extension.upper(),
                    sha256=digest,
                    crc32=f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
                )
                results.append(item)
                notify("carved", item)
        manifest = self.output / "carving_manifest.json"
        manifest.write_text(
            json.dumps(
                [{**item.__dict__, "output_path": str(item.output_path)} for item in results],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return results

    @staticmethod
    def _valid_image(data: bytes, extension: str) -> bool:
        if len(data) < 64:
            return False
        if Image is None:
            return extension == "jpg" and data.endswith(b"\xff\xd9") or (
                extension == "png" and b"IEND" in data[-16:]
            )
        try:
            with Image.open(BytesIO(data)) as image:
                expected = "JPEG" if extension == "jpg" else "PNG"
                if image.format != expected or image.width < 1 or image.height < 1:
                    return False
                image.verify()
            return True
        except Exception:
            return False

    @classmethod
    def _carve(cls, payload: bytes) -> Iterator[tuple[int, bytes, str]]:
        cursor = 0
        while cursor < len(payload):
            jpeg = payload.find(cls.JPEG_START, cursor)
            png = payload.find(cls.PNG_START, cursor)
            starts = [(jpeg, "jpg"), (png, "png")]
            starts = [(position, kind) for position, kind in starts if position >= 0]
            if not starts:
                return
            start, kind = min(starts)
            if kind == "jpg":
                marker = payload.find(cls.JPEG_END, start + len(cls.JPEG_START))
                if marker < 0:
                    cursor = start + len(cls.JPEG_START)
                    continue
                end = marker + len(cls.JPEG_END)
            else:
                marker = payload.find(cls.PNG_IEND, start + len(cls.PNG_START))
                if marker < 4 or marker + 8 > len(payload):
                    cursor = start + len(cls.PNG_START)
                    continue
                end = marker + 8
            yield start, payload[start:end], kind
            cursor = end


class WhatsAppDecryptor:
    @staticmethod
    def decrypt(encrypted: Path, key_file: Path, output: Path) -> dict[str, object]:
        if encrypted.is_symlink() or key_file.is_symlink() or output.is_symlink():
            raise ForensicError("No se aceptan enlaces simbólicos")
        encrypted = encrypted.resolve(strict=True)
        key_file = key_file.resolve(strict=True)
        if not encrypted.is_file() or not key_file.is_file():
            raise ForensicError("El backup y la clave deben ser archivos regulares")
        output = output.resolve()
        partial = output.with_suffix(output.suffix + ".partial")
        partial.unlink(missing_ok=True)
        executable = shutil.which("wadecrypt")
        command = (
            [executable, "-nm", str(key_file), str(encrypted), str(partial)]
            if executable
            else [
                sys.executable,
                "-m",
                "wa_crypt_tools.wadecrypt",
                "-nm",
                str(key_file),
                str(encrypted),
                str(partial),
            ]
        )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1800,
                check=False,
            )
        except FileNotFoundError as error:
            raise ForensicError("Instala wa-crypt-tools: python -m pip install wa-crypt-tools") from error
        if completed.returncode != 0 or not partial.is_file():
            partial.unlink(missing_ok=True)
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise ForensicError(f"No se pudo descifrar Crypt14: {detail}")
        with partial.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                partial.unlink(missing_ok=True)
                raise ForensicError("La clave no corresponde al backup: salida SQLite inválida")
        uri = f"{partial.as_uri()}?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=10) as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as error:
            partial.unlink(missing_ok=True)
            raise ForensicError(f"SQLite descifrada corrupta: {error}") from error
        if integrity is None or integrity[0] != "ok":
            partial.unlink(missing_ok=True)
            raise ForensicError("La base descifrada no superó PRAGMA integrity_check")
        partial.replace(output)
        return {
            "path": str(output),
            "size": output.stat().st_size,
            "sha256": hash_file(output),
            "integrity": "ok",
        }


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ChatViewer(tk.Toplevel):
    def __init__(self, parent: tk.Misc, database: Path) -> None:
        super().__init__(parent)
        self.title("Visor de chats — msgstore.db")
        self.geometry("1180x720")
        self.configure(bg="#091117")
        self.database = database
        self.table_list = tk.Listbox(
            self, bg="#111f27", fg="#dff2f3", selectbackground="#287f91", borderwidth=0
        )
        self.table_list.pack(side=LEFT, fill=Y, padx=(14, 5), pady=14)
        self.table_list.bind("<<ListboxSelect>>", self._load_table)
        frame = tk.Frame(self, bg="#091117")
        frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=(5, 14), pady=14)
        self.tree = ttk.Treeview(frame, show="headings")
        vertical = ttk.Scrollbar(frame, orient=VERTICAL, command=self.tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        for (name,) in tables:
            self.table_list.insert(END, name)
        if tables:
            self.table_list.selection_set(0)
            self._load_table()

    def _load_table(self, _event: object | None = None) -> None:
        selection = self.table_list.curselection()
        if not selection:
            return
        table = str(self.table_list.get(selection[0]))
        quoted = '"' + table.replace('"', '""') + '"'
        with sqlite3.connect(f"{self.database.as_uri()}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(f"SELECT * FROM {quoted} LIMIT 1000").fetchall()
            columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({quoted})")]
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = columns
        for column in columns:
            self.tree.heading(column, text=column)
            self.tree.column(column, width=180, minwidth=80)
        for row in rows:
            values = [
                value.hex()[:128] if isinstance(value, bytes) else str(value)[:2000]
                for value in row
            ]
            self.tree.insert("", END, values=values)


class CellebriteChat(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Forensic Mobile Lab — WhatsApp Auto-Scan")
        self.geometry("1040x700")
        self.minsize(820, 560)
        self.configure(bg="#081017")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.backup_path: Path | None = None
        self.key_path: Path | None = None
        self.preview_images: list[object] = []
        self._build_ui()
        self.after(100, self._consume_events)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", background="#24bddd", foreground="#041014", padding=11)
        style.map("TButton", background=[("active", "#55d6ec")])
        header = tk.Frame(self, bg="#0d251e", padx=24, pady=18)
        header.pack(fill=X)
        tk.Label(
            header,
            text="FORENSIC MOBILE LAB",
            bg="#0d251e",
            fg="#f1fbfb",
            font=("Helvetica", 24, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="WHATSAPP CRYPT14 · ADB PÚBLICO · INTEGRIDAD SQLITE",
            bg="#0d251e",
            fg="#55d9ec",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w", pady=(4, 0))
        controls = tk.Frame(self, bg="#081017", padx=24, pady=16)
        controls.pack(fill=X)
        self.scan_button = ttk.Button(
            controls,
            text="🔍 Auto-Escanear & Analizar",
            command=self.start_auto_scan,
        )
        self.scan_button.pack(side=LEFT)
        self.carve_button = ttk.Button(
            controls,
            text="🔍 Extracción Forense (Sin Root)",
            command=self.start_file_carving,
        )
        self.carve_button.pack(side=LEFT, padx=10)
        ttk.Button(
            controls,
            text="Seleccionar clave manualmente…",
            command=self.select_key_manually,
        ).pack(side=LEFT, padx=10)
        self.status = tk.Label(
            controls,
            text="● LISTO",
            bg="#081017",
            fg="#55ef9e",
            font=("Helvetica", 10, "bold"),
        )
        self.status.pack(side=RIGHT)
        console_frame = tk.Frame(self, bg="#14222a", padx=1, pady=1)
        console_frame.pack(fill=BOTH, expand=True, padx=24, pady=(0, 24))
        self.console = tk.Text(
            console_frame,
            bg="#0c151b",
            fg="#bfe6dc",
            insertbackground="white",
            font=("Menlo", 11),
            borderwidth=0,
            padx=16,
            pady=16,
            state="disabled",
            wrap="word",
        )
        scrollbar = ttk.Scrollbar(console_frame, command=self.console.yview)
        self.console.configure(yscrollcommand=scrollbar.set)
        self.console.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.preview_frame = tk.Frame(self, bg="#081017", padx=24, pady=8)
        self.preview_frame.pack(fill=X, before=console_frame)
        tk.Label(
            self.preview_frame,
            text="RECUPERACIÓN POR FIRMAS · VISTA PREVIA",
            bg="#081017",
            fg="#55d9ec",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w")
        self.preview_strip = tk.Frame(self.preview_frame, bg="#081017")
        self.preview_strip.pack(fill=X, pady=(8, 0))
        self.log("Conecta un Android desbloqueado con Depuración USB autorizada.")
        self.log("El escaneo está limitado a /sdcard y /storage/emulated/0.")

    def start_auto_scan(self) -> None:
        self.scan_button.configure(state="disabled")
        self.status.configure(text="● ESCANEANDO", fg="#55d9ec")
        threading.Thread(target=self._auto_scan_worker, daemon=True).start()

    def start_file_carving(self) -> None:
        self.carve_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.status.configure(text="● FILE CARVING", fg="#55d9ec")
        for widget in self.preview_strip.winfo_children():
            widget.destroy()
        self.preview_images.clear()
        threading.Thread(target=self._file_carving_worker, daemon=True).start()

    def _file_carving_worker(self) -> None:
        try:
            adb = ADBClient()
            serial = adb.connect()
            self.emit_log(f"File carving lógico iniciado en {serial}")
            engine = CellebriteLiteEngine(adb)
            results = engine.scan_device(lambda kind, value: self.emit((kind, value)))
            self.emit_log(
                f"✅ Escaneo terminado: {len(results)} imágenes delimitadas por firma\n"
                f"Salida: {engine.output}\nManifest: {engine.output / 'carving_manifest.json'}"
            )
            self.emit(("carving_done", len(results)))
        except Exception as error:
            self.emit(("error", str(error)))
        finally:
            self.emit(("idle", None))

    def _show_carved_preview(self, item: CarvedImage) -> None:
        if len(self.preview_images) >= 12 or Image is None or ImageTk is None:
            return
        try:
            with Image.open(item.output_path) as source:
                source.verify()
            with Image.open(item.output_path) as source:
                preview = source.convert("RGB")
                preview.thumbnail((110, 110))
                rendered = ImageTk.PhotoImage(preview)
            self.preview_images.append(rendered)
            tile = tk.Label(
                self.preview_strip,
                image=rendered,
                text=f"{item.kind}\n{item.size:,} B",
                compound="top",
                bg="#10222a",
                fg="#d8eeee",
                padx=5,
                pady=5,
            )
            tile.pack(side=LEFT, padx=(0, 8))
        except Exception as error:
            self.log(f"Fragmento descartado de la vista previa: {error}")

    def _auto_scan_worker(self) -> None:
        try:
            self.emit_log("Escaneando dispositivos ADB…")
            adb = ADBClient()
            serial = adb.connect()
            self.emit_log(f"Dispositivo autorizado: {serial}")
            self.emit_log("Escaneando recursivamente almacenamiento público…")
            backups = adb.scan_backups()
            if not backups:
                raise ForensicError("No se encontraron backups .db.crypt14 accesibles")
            selected = backups[0]
            self.emit_log(
                f"Backup más reciente: {selected.path} (mtime={selected.modified_at})"
            )
            self.emit_log("Calculando SHA-256/CRC32 mientras se copia…")
            backup = adb.copy_public_file(selected.path, LOCAL_BACKUP)
            self.backup_path = backup.local_path
            self.emit_log(
                f"Backup guardado: {backup.local_path}\n"
                f"SHA-256: {backup.sha256}\nCRC32: {backup.crc32}\nBytes: {backup.size}"
            )
            self.emit_log("Buscando archivo key junto al backup y en rutas públicas…")
            remote_key = adb.find_public_key(selected.path)
            if remote_key:
                key_result = adb.copy_public_file(remote_key, LOCAL_KEY)
                os.chmod(key_result.local_path, 0o600)
                self.key_path = key_result.local_path
                self.emit_log(
                    f"Clave pública encontrada: {remote_key}\n"
                    f"Clave copiada completa: {key_result.local_path}\n"
                    f"SHA-256 clave: {key_result.sha256}"
                )
                self.emit_log("✅ Extracción completa: Archivo y Clave detectados. Analizando…")
                self._decrypt_and_validate()
            else:
                self.emit(("key_missing", None))
        except Exception as error:
            self.emit(("error", str(error)))
        finally:
            self.emit(("idle", None))

    def select_key_manually(self) -> None:
        selected = filedialog.askopenfilename(
            title="Selecciona la clave correspondiente al backup Crypt14"
        )
        if not selected:
            return
        self.key_path = Path(selected).resolve()
        self.log(f"Clave seleccionada manualmente: {self.key_path}")
        if self.backup_path:
            self.scan_button.configure(state="disabled")
            self.status.configure(text="● DESCIFRANDO", fg="#f2c75f")
            threading.Thread(target=self._manual_decrypt_worker, daemon=True).start()

    def _manual_decrypt_worker(self) -> None:
        try:
            self._decrypt_and_validate()
        except Exception as error:
            self.emit(("error", str(error)))
        finally:
            self.emit(("idle", None))

    def _decrypt_and_validate(self) -> None:
        if not self.backup_path or not self.key_path:
            raise ForensicError("Falta el backup o la clave")
        self.emit_log("Descifrando con wa-crypt-tools…")
        result = WhatsAppDecryptor.decrypt(
            self.backup_path, self.key_path, DECRYPTED_DB
        )
        self.emit_log(
            "✅ Éxito: SQLite descifrada y validada\n"
            f"Ruta: {result['path']}\nSHA-256: {result['sha256']}\n"
            f"Integridad: {result['integrity']}"
        )
        self.emit(("open_viewer", DECRYPTED_DB))

    def emit_log(self, message: str) -> None:
        self.emit(("log", message))

    def emit(self, event: tuple[str, object]) -> None:
        self.events.put(event)

    def _consume_events(self) -> None:
        while True:
            try:
                name, value = self.events.get_nowait()
            except queue.Empty:
                break
            if name == "log":
                self.log(str(value))
            elif name == "error":
                self.log(f"ERROR: {value}")
                messagebox.showerror("Forensic Mobile Lab", str(value))
            elif name == "key_missing":
                self.log("⚠️ Backup encontrado, pero falta la clave en esta carpeta")
                messagebox.showwarning(
                    "Clave no encontrada",
                    "Backup encontrado, pero falta la clave en esta carpeta. "
                    "Selecciona la clave manualmente si la tienes.",
                )
                self.select_key_manually()
            elif name == "open_viewer":
                self.status.configure(text="● ANÁLISIS COMPLETO", fg="#55ef9e")
                ChatViewer(self, Path(str(value)))
            elif name == "carved" and isinstance(value, CarvedImage):
                self.log(
                    f"RECUPERADO {value.kind}: {value.output_path.name}\n"
                    f"Origen: {value.source_path} @ {value.offset}\n"
                    f"SHA-256: {value.sha256} · CRC32: {value.crc32}"
                )
                self._show_carved_preview(value)
            elif name == "carving_done":
                self.status.configure(text=f"● CARVING COMPLETO ({value})", fg="#55ef9e")
            elif name == "idle":
                self.scan_button.configure(state="normal")
                self.carve_button.configure(state="normal")
                if self.status.cget("text") != "● ANÁLISIS COMPLETO":
                    self.status.configure(text="● LISTO", fg="#55ef9e")
        self.after(100, self._consume_events)

    def log(self, message: str) -> None:
        self.console.configure(state="normal")
        self.console.insert(END, message.rstrip() + "\n\n")
        self.console.see(END)
        self.console.configure(state="disabled")


if __name__ == "__main__":
    CellebriteChat().mainloop()
