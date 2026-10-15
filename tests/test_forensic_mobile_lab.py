from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import sqlite3
import shutil
import sys
import tempfile
import unittest
import zlib
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "forensic_mobile_lab.py"
SPEC = importlib.util.spec_from_file_location("forensic_mobile_lab", MODULE_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


class ForensicCoreTests(unittest.TestCase):
    def test_cli_demo_uses_private_case_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            previous = os.umask(0o022)
            try:
                self.assertEqual(lab.main(["demo", "--workspace", str(workspace)]), 0)
            finally:
                os.umask(previous)
            self.assertEqual(workspace.stat().st_mode & 0o077, 0)
            self.assertEqual((workspace / "case").stat().st_mode & 0o077, 0)
            report = workspace / "case/reports/forensic_report.json"
            self.assertEqual(report.stat().st_mode & 0o077, 0)

    def test_report_preserves_legal_authority_and_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            device, case = workspace / "device", workspace / "case"
            lab.create_demo_device(device)
            case.mkdir()
            (case / "case_profile.json").write_text(json.dumps({
                "case_number": "PR-2026-001",
                "examiner": "Analista autorizado",
                "examiner_id": "LAB-42",
                "legal_authority": "Consentimiento documentado",
                "authorized_scope": "Almacenamiento compartido y comunicaciones",
                "authorization_confirmed": True,
            }), encoding="utf-8")
            reports = lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), case).run()
            payload = json.loads(reports["json"].read_text(encoding="utf-8"))
            self.assertTrue(payload["case_profile"]["authorization_confirmed"])
            html = reports["html"].read_text(encoding="utf-8")
            self.assertIn("Consentimiento documentado", html)
            self.assertIn("Almacenamiento compartido y comunicaciones", html)

    def test_demo_produces_verified_searchable_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            device = workspace / "device"
            case = workspace / "case"
            lab.create_demo_device(device)
            reports = lab.CellebriteCloneCore(
                lab.SimulatedMobileTransport(device), case
            ).run()
            payload = json.loads(reports["json"].read_text(encoding="utf-8"))
            self.assertEqual(len(payload["manifest"]), 3)
            self.assertEqual(payload["evidence_quality"]["empty_files"], 0)
            self.assertEqual(payload["methodology"]["acquisition_type"], "AUTHORIZED_LOGICAL_ADB")
            self.assertEqual(payload["evidence_classification"]["CONFIRMED_DELETED"], 0)
            self.assertIn("no asignado", payload["methodology"]["excluded"])
            self.assertIn("borrados confirmados 0", reports["html"].read_text(encoding="utf-8"))
            with sqlite3.connect(reports["search_index"]) as connection:
                count = connection.execute(
                    "SELECT count(*) FROM search WHERE search MATCH ?", ("laboratorio",)
                ).fetchone()[0]
            self.assertEqual(count, 1)
            master = json.loads(reports["case_master_manifest"].read_text(encoding="utf-8"))
            self.assertGreaterEqual(master["files_count"], 8)

    def test_semantic_custody_tamper_fails_even_after_reseal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device, case = root / "device", root / "case"
            lab.create_demo_device(device)
            reports = lab.CellebriteCloneCore(
                lab.SimulatedMobileTransport(device), case
            ).run()
            custody_path = reports["chain_of_custody"]
            custody = json.loads(custody_path.read_text(encoding="utf-8"))
            custody["events"][0]["event"] = "ACQUISITION_STARTED_EDITED"
            custody_path.write_text(json.dumps(custody), encoding="utf-8")
            # Simula a alguien que vuelve a generar solamente los hashes de archivos.
            lab.ForensicReporter._write_master_manifest(
                reports["case_master_manifest"], case
            )
            result = lab.main(["verify", str(reports["json"])])
            verification = json.loads(
                (case / "reports/integrity_verification.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result, 4)
            self.assertFalse(verification["hash_chains_valid"])
            self.assertFalse(verification["all_valid"])

    def test_checkpoint_is_complete_and_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            device = workspace / "device"
            case = workspace / "case"
            lab.create_demo_device(device)
            lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), case).run()
            checkpoint = json.loads(
                (case / "acquisition_checkpoint.json").read_text(encoding="utf-8")
            )
            self.assertEqual(checkpoint["status"], "complete")
            self.assertEqual(len(checkpoint["files"]), 3)

    def test_unsafe_remote_path_is_rejected(self) -> None:
        with self.assertRaises(lab.DevicePermissionError):
            lab.RealADBTransport._validate_remote_path("/sdcard/../data/secret.db")

    def test_public_storage_roots_are_valid_scan_entrypoints(self) -> None:
        self.assertEqual(
            lab.RealADBTransport._validate_remote_path("/sdcard"), "/sdcard"
        )
        self.assertEqual(
            lab.RealADBTransport._validate_remote_path("/storage/emulated/0"),
            "/storage/emulated/0",
        )

    def test_checkpoint_rejects_external_file_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = root / "case"
            evidence = case / "evidence"
            evidence.mkdir(parents=True)
            outside = root / "outside.bin"
            outside.write_bytes(b"external")
            link = evidence / "link.bin"
            link.symlink_to(outside)
            self.assertFalse(lab.DeviceHandler._is_safe_checkpoint_file(outside, case))
            self.assertFalse(lab.DeviceHandler._is_safe_checkpoint_file(link, case))

    def test_master_manifest_includes_hidden_files_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); case = root / "case"
            reports = case / "reports"; evidence = case / "evidence"
            reports.mkdir(parents=True); evidence.mkdir()
            hidden = evidence / ".hidden-evidence"; hidden.write_bytes(b"visible al sello")
            manifest = reports / "case_master_manifest.json"
            lab.ForensicReporter._write_master_manifest(manifest, case)
            paths = {item["path"] for item in json.loads(manifest.read_text())["files"]}
            self.assertIn("evidence/.hidden-evidence", paths)
            outside = root / "outside.bin"; outside.write_bytes(b"privado")
            (evidence / "escape.bin").symlink_to(outside)
            with self.assertRaises(lab.DevicePermissionError):
                lab.ForensicReporter._write_master_manifest(manifest, case)

    def test_acquisition_rejects_symlinked_case_internals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); device = root / "device"; case = root / "case"
            lab.create_demo_device(device); case.mkdir()
            outside = root / "outside"; outside.mkdir()
            (case / "evidence").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(lab.DevicePermissionError):
                lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), case)

    def test_redacted_copy_removes_phone_and_gps_without_touching_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "report.json"; output = root / "redacted.json"
            payload = {"address": "+1 787 555 1212", "jid": "15550000003@s.whatsapp.net", "latitude": 18.4, "nested": ["Llame al +1 (787) 555-1212"]}
            source.write_text(json.dumps(payload), encoding="utf-8")
            before = source.read_bytes()
            self.assertEqual(lab.main(["redact", str(source), str(output)]), 0)
            redacted = output.read_text(encoding="utf-8")
            self.assertNotIn("15550000003", redacted)
            self.assertNotIn("787", redacted)
            self.assertIn("[REDACTED]", redacted)
            self.assertEqual(source.read_bytes(), before)

    def test_tampered_checkpoint_entry_is_reacquired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            device, case = workspace / "device", workspace / "case"
            lab.create_demo_device(device)
            core = lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), case)
            core.run()
            checkpoint_path = case / "acquisition_checkpoint.json"
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            logical = next(iter(checkpoint["files"]))
            checkpoint["files"][logical]["logical_path"] = "ruta/falsificada.db"
            checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
            reports = lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), case).run()
            payload = json.loads(reports["json"].read_text(encoding="utf-8"))
            self.assertIn(logical, {item["logical_path"] for item in payload["manifest"]})
            repaired = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            self.assertEqual(repaired["files"][logical]["logical_path"], logical)

    def test_corrupt_sqlite_isolated_as_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "broken.db"
            database.write_bytes(b"not sqlite")
            entry = lab.FileManifestEntry(
                logical_path="broken.db", evidence_path=str(database), size=10,
                sha256="0" * 64, crc32="00000000", acquired_at=lab._utc_now(),
            )
            artifacts, warnings = lab.DatabaseParser().parse([entry])
            self.assertEqual(artifacts, [])
            self.assertEqual(len(warnings), 1)

    def test_verifier_detects_modified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            device, case = workspace / "device", workspace / "case"
            lab.create_demo_device(device)
            reports = lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), case).run()
            payload = json.loads(reports["json"].read_text(encoding="utf-8"))
            Path(payload["manifest"][0]["evidence_path"]).write_bytes(b"tampered")
            self.assertEqual(lab.main(["verify", str(reports["json"])]), 4)

    def test_case_remains_verifiable_after_being_moved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            device, original = workspace / "device", workspace / "original-case"
            lab.create_demo_device(device)
            lab.CellebriteCloneCore(lab.SimulatedMobileTransport(device), original).run()
            moved = workspace / "external-drive" / "moved-case"
            moved.parent.mkdir()
            shutil.move(str(original), moved)
            report = moved / "reports/forensic_report.json"
            self.assertEqual(lab.main(["verify", str(report)]), 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(all(item["case_relative_path"] for item in payload["manifest"]))

    def test_adb_stream_yields_bounded_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-adb"
            executable.write_text("#!/bin/sh\nprintf 'abcdefghijklmnopqrstuvwxyz'\n", encoding="utf-8")
            executable.chmod(0o700)
            transport = lab.RealADBTransport(adb_path=str(executable))
            transport._connected = True
            chunks = list(transport.read_file_chunks("/sdcard/test.mp4", 5))
            self.assertEqual(b"".join(chunk for chunk, _ in chunks), b"abcdefghijklmnopqrstuvwxyz")
            self.assertTrue(all(len(chunk) <= 5 for chunk, _ in chunks))
            self.assertTrue(all(crc == lab.zlib.crc32(chunk) & 0xFFFFFFFF for chunk, crc in chunks))

    def test_public_whatsapp_pair_prefers_latest_and_adjacent_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-adb"
            executable.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *\"find /sdcard\"*) printf '/sdcard/X/old.db.crypt14\\n/sdcard/X/key\\n' ;;\n"
                "  *\"find /storage/emulated/0\"*) printf '/storage/emulated/0/Y/msgstore.db.crypt14\\n' ;;\n"
                "  *\"stat -c %Y /sdcard/X/old.db.crypt14\"*) printf '100\\n' ;;\n"
                "  *\"stat -c %Y /storage/emulated/0/Y/msgstore.db.crypt14\"*) printf '200\\n' ;;\n"
                "  *\"test -f /storage/emulated/0/Y/key\"*) printf 'FOUND\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            transport = lab.RealADBTransport(adb_path=str(executable))
            transport._connected = True
            pair = transport.find_whatsapp_pair()
            self.assertIsNotNone(pair)
            self.assertEqual(pair["backup"], "/storage/emulated/0/Y/msgstore.db.crypt14")
            self.assertEqual(pair["key"], "/storage/emulated/0/Y/key")

    def test_carving_streams_chunks_and_records_source_provenance(self) -> None:
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow no disponible")
        image = io.BytesIO()
        Image.new("RGB", (18, 12), (20, 130, 220)).save(image, "PNG")
        payload = b"container-prefix" + image.getvalue() + b"container-suffix"

        class ChunkedTransport:
            def iter_all_public_files(self):
                yield "/sdcard/Fotos con acento/ámbito.bin"
            def read_file_chunks(self, path, chunk_size):
                del path, chunk_size
                for offset in range(0, len(payload), 7):
                    chunk = payload[offset:offset + 7]
                    yield chunk, zlib.crc32(chunk) & 0xFFFFFFFF
            def remote_file_metadata(self, path):
                del path
                return {"size": len(payload), "mtime": 1234}

        with tempfile.TemporaryDirectory() as temporary:
            report = lab.ADBFileCarvingEngine(
                ChunkedTransport(), Path(temporary)
            ).run()
            self.assertEqual(report["recovered_count"], 1)
            item = report["images"][0]
            self.assertEqual(item["classification"], "EMBEDDED_IMAGE")
            self.assertEqual(item["deletion_status"], "UNDETERMINED")
            self.assertEqual(item["source_stability"], "STABLE")
            self.assertEqual(item["source_sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(item["source_crc32"], f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}")
            self.assertFalse(any(Path(temporary).glob(".source-scan-*")))
            standard_report = Path(temporary) / "reports/forensic_report.json"
            self.assertTrue(standard_report.is_file())
            self.assertEqual(lab.main(["verify", str(standard_report)]), 0)

    def test_carving_marks_source_changed_during_acquisition(self) -> None:
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow no disponible")
        image = io.BytesIO()
        Image.new("RGB", (8, 8), "red").save(image, "JPEG")
        payload = image.getvalue()

        class ChangingTransport:
            calls = 0
            def iter_all_public_files(self): yield "/sdcard/photo.jpg"
            def read_file_chunks(self, path, chunk_size):
                del path, chunk_size
                yield payload, zlib.crc32(payload) & 0xFFFFFFFF
            def remote_file_metadata(self, path):
                del path
                self.calls += 1
                return {"size": len(payload), "mtime": self.calls}

        with tempfile.TemporaryDirectory() as temporary:
            report = lab.ADBFileCarvingEngine(
                ChangingTransport(), Path(temporary)
            ).run()
            item = report["images"][0]
            self.assertEqual(item["source_stability"], "CHANGED_DURING_ACQUISITION")
            self.assertEqual(item["classification"], "COMPLETE_VISIBLE_FILE")
            self.assertFalse(item["is_recovered"])

    def test_carving_rejects_truncated_and_duplicate_images(self) -> None:
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow no disponible")
        image = io.BytesIO()
        Image.new("RGB", (10, 10), "green").save(image, "PNG")
        complete = image.getvalue()
        payload = complete + b"noise" + complete + b"\x89PNG\r\n\x1a\ntruncated"

        class Transport:
            def iter_all_public_files(self): yield "/sdcard/repeated.bin"
            def read_file_chunks(self, path, chunk_size):
                del path, chunk_size
                yield payload, 0

        with tempfile.TemporaryDirectory() as temporary:
            report = lab.ADBFileCarvingEngine(Transport(), Path(temporary)).run()
            self.assertEqual(report["recovered_count"], 1)

    def test_termination_signal_is_a_controlled_cancellation(self) -> None:
        with self.assertRaises(KeyboardInterrupt):
            lab._termination_signal(15, None)

    def test_sqlite_audit_reports_schema_and_wal_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, report_path = root / "messages.db", root / "sqlite-report.json"
            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.execute("CREATE TABLE message(id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO message(body) VALUES ('candidate printable forensic text')")
                connection.commit()
                report = lab.audit_sqlite_database(database, report_path)
            finally:
                connection.close()
            self.assertEqual(report["integrity"], "ok")
            self.assertEqual(report["tables"][0]["name"], "message")
            self.assertGreaterEqual(len(report["sidecars"]), 1)
            self.assertTrue(any(item["path"].endswith("-wal") for item in report["sidecars"]))
            self.assertEqual(
                report["candidate_strings"][0]["classification"],
                "UNVERIFIED_PRINTABLE_SEQUENCE",
            )
            self.assertTrue(report_path.is_file())

    def test_apk_audit_inventory_is_static_and_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk, report_path = root / "sample.apk", root / "apk-report.json"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"binary-axml")
                archive.writestr("classes.dex", b"dex\n035\x00")
                archive.writestr("lib/arm64-v8a/libsample.so", b"mach-o")
                archive.writestr("META-INF/CERT.RSA", b"signature")
            report = lab.audit_apk(apk, report_path)
            self.assertTrue(report["has_manifest"])
            self.assertEqual(report["dex_files"], ["classes.dex"])
            self.assertEqual(len(report["native_libraries"]), 1)
            self.assertEqual(report["sha256"], hashlib.sha256(apk.read_bytes()).hexdigest())

    def test_content_provider_parser_preserves_commas_in_sms_body(self) -> None:
        output = (
            "Row: 0 _id=7, address=+15551234567, date=1710000000000, "
            "type=1, body=Hola, esto conserva, las comas\n"
        )
        rows = lab.RealADBTransport._parse_content_rows(output)
        self.assertEqual(rows[0]["_id"], "7")
        self.assertEqual(rows[0]["body"], "Hola, esto conserva, las comas")

    def test_android_contacts_and_sms_logical_extraction(self) -> None:
        class FakeTransport(lab.RealADBTransport):
            def __init__(self):
                self._connected = True
                self._serial = "LAB123"
            def identity(self):
                return lab.DeviceIdentity(
                    serial="LAB123", manufacturer="Lab", model="Phone",
                    platform="Android", os_version="15", transport="ADB",
                )
            def _run_adb(self, args, timeout, use_serial=True):
                del timeout, use_serial
                joined = " ".join(args)
                if "contacts" in joined:
                    return 0, "Row: 0 display_name=Ana, number=5551234, type=2, contact_id=4\n", ""
                if "content://sms" in joined:
                    return 0, "Row: 0 _id=1, thread_id=2, address=5551234, date=1710000000000, date_sent=0, type=1, read=1, body=Mensaje de prueba\n", ""
                return 1, "", "denied"

        report = FakeTransport().extract_public_communications()
        self.assertEqual(report["contacts_count"], 1)
        self.assertEqual(report["sms_count"], 1)
        self.assertEqual(report["contacts"][0]["display_name"], "Ana")
        self.assertIn("date_utc", report["sms"][0])
        self.assertEqual(report["acquisition_type"], "EXTRACCION_LOGICA_ADB")

    def test_chrome_history_extracts_visits_searches_and_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, output = root / "History", root / "chrome.json"
            chrome_epoch = 11_644_473_600 * 1_000_000
            with sqlite3.connect(database) as connection:
                connection.executescript(
                    "CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER);"
                    "CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER,visit_duration INTEGER);"
                    "CREATE TABLE keyword_search_terms(keyword_id INTEGER,url_id INTEGER,term TEXT,normalized_term TEXT);"
                    "CREATE TABLE downloads(id INTEGER PRIMARY KEY,target_path TEXT,tab_url TEXT,start_time INTEGER,end_time INTEGER,total_bytes INTEGER);"
                )
                connection.execute("INSERT INTO urls VALUES(1,'https://example.test','Example',1,1)")
                connection.execute("INSERT INTO visits VALUES(1,1,?,0,1,10)", (chrome_epoch + 1_710_000_000_000_000,))
                connection.execute("INSERT INTO keyword_search_terms VALUES(1,1,'forense android','forense android')")
                connection.execute("INSERT INTO downloads VALUES(1,'/sdcard/a.pdf','https://example.test',?,?,42)", (chrome_epoch + 1_710_000_000_000_000, chrome_epoch + 1_710_000_001_000_000))
            report = lab.analyze_chrome_history(database, output)
            self.assertEqual(report["integrity"], "ok")
            self.assertEqual(report["visits_count"], 1)
            self.assertEqual(report["searches_count"], 1)
            self.assertEqual(report["downloads_count"], 1)
            self.assertEqual(report["visits"][0]["visit_time_utc"], "2024-03-09T16:00:00+00:00")
            self.assertEqual(report["source_sha256"], hashlib.sha256(database.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
