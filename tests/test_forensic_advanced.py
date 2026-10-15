import json, sqlite3, subprocess, tempfile, unittest, zipfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import forensic_advanced as fa

class AdvancedTests(unittest.TestCase):
    def case(self, root):
        c=Path(root)/"case"; (c/"evidence").mkdir(parents=True)
        (c/"evidence/a.txt").write_text("ana@example.com +1 787 555 1212 18.4655,-66.1057 evidencia alfa")
        (c/"evidence/b.txt").write_text("ana@example.com +1 787 555 1212 18.4655,-66.1057 evidencia alfa")
        db=sqlite3.connect(c/"evidence/chat.db"); db.execute("create table messages(id integer,text text)"); db.execute("insert into messages values(1,'hola')"); db.commit(); db.close()
        return c
    def test_build_rag_citations_and_chain(self):
        with tempfile.TemporaryDirectory() as d:
            c=self.case(d); (c/"evidence/manual.pdf").write_bytes(b"%PDF-1.4\n"); (c/"evidence/video.mkv").write_bytes(b"video")
            (c/".ui_cache").mkdir(); (c/".ui_cache/ui_gallery.html").write_text("caché regenerable")
            r=fa.build(c); self.assertEqual(r["locations"],2); self.assertEqual(r["duplicate_groups"],1)
            self.assertEqual(r["categories"]["PDF"],1); self.assertEqual(r["categories"]["VIDEOS"],1)
            self.assertTrue((c/"reports/advanced/file_catalog.html").exists())
            self.assertEqual(r["quality_control"]["status"],"PASS")
            self.assertTrue((c/"reports/advanced/relationship_graph.json").exists())
            catalog=json.loads((c/"reports/advanced/file_catalog.json").read_text())
            self.assertNotIn(".ui_cache/ui_gallery.html", {item["path"] for item in catalog["files"]})
            q=fa.ask(c,"evidencia alfa"); self.assertTrue(q["citations"]); self.assertIn("sha256",q["citations"][0])
            chain=json.loads((c/"reports/advanced/custody_chain.json").read_text()); self.assertEqual(chain[0]["previous_hash"],"")
    def test_compare_portable_and_ios(self):
        with tempfile.TemporaryDirectory() as d:
            a=self.case(Path(d)/"a"); b=self.case(Path(d)/"b"); (b/"evidence/new.txt").write_text("nuevo")
            self.assertIn("evidence/new.txt",fa.compare(a,b)["added"])
            fa.build(a); (a/"reports/case_signature.json").write_text('{"test":"signature"}')
            out=Path(d)/"case.zip"; meta=fa.portable(a,out); self.assertGreater(meta["files"],0)
            extracted=Path(d)/"portable"
            with zipfile.ZipFile(out) as z:
                self.assertIn("verify_portable.py",z.namelist())
                self.assertIn("reports/case_signature.json",z.namelist())
                self.assertIn("reports/advanced/file_catalog.json",z.namelist())
                z.extractall(extracted)
            self.assertEqual(subprocess.run([sys.executable,"verify_portable.py"],cwd=extracted).returncode,0)
            (extracted/"unexpected.bin").write_bytes(b"extra")
            self.assertNotEqual(subprocess.run([sys.executable,"verify_portable.py"],cwd=extracted).returncode,0)
            ios=Path(d)/"ios";ios.mkdir();(ios/"Manifest.db").write_bytes(b"");self.assertTrue(fa.ios_inventory(ios,Path(d)/"ios.json")["recognized"])
    def test_resumable_read_only_imaging(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"source.bin"; source.write_bytes(b"0123456789"*1000)
            output=Path(d)/"image.dd"; output.write_bytes(source.read_bytes()[:123])
            result=fa.image_source(source,output,"READ-ONLY-source.bin",chunk=64)
            self.assertEqual(source.read_bytes(),output.read_bytes()); self.assertEqual(result["mode"],"READ_ONLY_SOURCE")
            self.assertEqual(result["source_sha256"], result["sha256"])
            self.assertEqual(result["source_stability"], "STABLE")
    def test_imaging_rejects_wrong_resume_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"source.bin"; source.write_bytes(b"fuente-correcta")
            output=Path(d)/"image.dd"; output.write_bytes(b"XXXXX")
            with self.assertRaisesRegex(ValueError, "no coincide"):
                fa.image_source(source,output,"READ-ONLY-source.bin",chunk=4)
    def test_security_rejects_symlink_roots_and_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); case=self.case(root/"real")
            linked_case=root/"linked-case"; linked_case.symlink_to(case, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "enlace simbólico"):
                fa.build(linked_case)
            real_output=root/"real-image.dd"; real_output.write_bytes(b"no tocar")
            linked_output=root/"linked-image.dd"; linked_output.symlink_to(real_output)
            source=root/"source.bin"; source.write_bytes(b"evidencia")
            with self.assertRaisesRegex(ValueError, "enlace simbólico"):
                fa.image_source(source,linked_output,"READ-ONLY-source.bin")
            self.assertEqual(real_output.read_bytes(), b"no tocar")
            zip_target=root/"real.zip"; zip_target.write_bytes(b"no tocar")
            zip_link=root/"linked.zip"; zip_link.symlink_to(zip_target)
            with self.assertRaisesRegex(ValueError, "enlace simbólico"):
                fa.portable(case,zip_link)
            self.assertEqual(zip_target.read_bytes(), b"no tocar")
