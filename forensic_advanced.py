#!/usr/bin/env python3
"""Advanced, read-only forensic analysis for an already acquired case.

No bypass, exploit or device modification is performed. Physical images and iOS
backups are accepted only as examiner-supplied, authorized evidence containers.
"""
from __future__ import annotations

import argparse, csv, hashlib, html, json, mimetypes, os, plistlib, re, sqlite3, subprocess, sys, zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

TEXT_EXT = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".md"}
MEDIA_EXT = {".jpg", ".jpeg", ".png", ".heic", ".mp4", ".mov", ".m4a", ".wav"}
VIDEO_EXT = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".wmv", ".flv", ".mpeg", ".mpg", ".3gp", ".mts", ".m2ts", ".vob", ".ogv"}
AUDIO_EXT = {".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus", ".amr", ".wma", ".aiff"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".tif", ".tiff", ".bmp", ".dng", ".raw"}
DOCUMENT_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".rtf", ".pages", ".numbers", ".key"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".dmg", ".iso", ".e01", ".aff4"}

def category(p: Path) -> str:
    ext=p.suffix.lower()
    if ext==".pdf": return "PDF"
    if ext in VIDEO_EXT: return "VIDEOS"
    if ext in AUDIO_EXT: return "AUDIOS"
    if ext in IMAGE_EXT: return "IMAGENES"
    if ext in DOCUMENT_EXT or ext in TEXT_EXT: return "DOCUMENTOS"
    if ext in {".db", ".sqlite", ".sqlite3", ".wal", ".shm"}: return "BASES_DE_DATOS"
    if ext in ARCHIVE_EXT: return "COMPRIMIDOS_E_IMAGENES_DISCO"
    if ext in {".app", ".exe", ".dll", ".dylib", ".apk", ".ipa", ".msi", ".pkg"}: return "APLICACIONES_Y_BINARIOS"
    return "OTROS"

def detected_type(p: Path) -> str:
    try:
        with p.open("rb") as stream: head=stream.read(32)
    except OSError: return "unreadable"
    signatures=[(b"%PDF-","pdf"),(b"\x89PNG\r\n\x1a\n","png"),(b"\xff\xd8\xff","jpeg"),(b"PK\x03\x04","zip/ooxml/apk"),(b"SQLite format 3\x00","sqlite"),(b"MZ","windows-executable"),(b"\x7fELF","elf-executable")]
    for magic,name in signatures:
        if head.startswith(magic): return name
    if len(head)>=12 and head[4:8]==b"ftyp": return "iso-base-media"
    return "unknown"

def expected_types(ext: str) -> set[str]:
    return {".pdf":{"pdf"},".png":{"png"},".jpg":{"jpeg"},".jpeg":{"jpeg"},".db":{"sqlite"},".sqlite":{"sqlite"},".exe":{"windows-executable"},".mp4":{"iso-base-media"},".mov":{"iso-base-media"}}.get(ext,set())

def utc() -> str: return datetime.now(timezone.utc).isoformat()
def safe_directory(path: Path, label="La carpeta") -> Path:
    if path.is_symlink(): raise ValueError(f"{label} no puede ser un enlace simbólico")
    resolved=path.resolve(strict=True)
    if not resolved.is_dir(): raise ValueError(f"{label} no es un directorio válido")
    return resolved
def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()
def atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if path.is_symlink() or tmp.is_symlink(): raise ValueError("La salida segura no puede ser un enlace simbólico")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600); os.replace(tmp, path)
def files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink(): continue
        try: relative=p.relative_to(root)
        except ValueError: continue
        if ".ui_cache" in relative.parts: continue
        if relative.parts[:2] == ("reports", "advanced"): continue
        if relative.as_posix() in {
            "reports/case_signature.json",
            "reports/case_master_manifest.json",
            "reports/integrity_verification.json",
        }: continue
        yield p
def text_of(p: Path, limit=2_000_000) -> str:
    if p.suffix.lower() not in TEXT_EXT: return ""
    try: return p.read_bytes()[:limit].decode("utf-8", "replace")
    except OSError: return ""
def event(action: str, details: dict[str, Any], previous="") -> dict[str, Any]:
    base={"timestamp_utc":utc(),"action":action,"details":details,"previous_hash":previous}
    base["event_hash"]=hashlib.sha256(json.dumps(base,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    return base

def build(case: Path) -> dict[str, Any]:
    case=safe_directory(case,"El expediente")
    reports_root=case/"reports"
    if reports_root.is_symlink(): raise ValueError("La carpeta reports no puede ser un enlace simbólico")
    reports_root.mkdir(parents=True,exist_ok=True)
    report=reports_root/"advanced"
    if report.is_symlink(): raise ValueError("La carpeta advanced no puede ser un enlace simbólico")
    report.mkdir(parents=True,exist_ok=True); os.chmod(report,0o700)
    docs=[]; timeline=[]; locations=[]; duplicates={}; catalog=[]; mismatches=[]; category_counts={}; entities={"emails":set(),"phones":set(),"urls":set()}
    for p in files(case):
        rel=p.relative_to(case).as_posix(); digest=sha(p); duplicates.setdefault(digest,[]).append(rel)
        stat=p.stat(); content=text_of(p); ts=datetime.fromtimestamp(stat.st_mtime,timezone.utc).isoformat(); kind=category(p)
        category_counts[kind]=category_counts.get(kind,0)+1
        actual=detected_type(p); expected=expected_types(p.suffix.lower()); mismatch=bool(expected and actual not in expected)
        row={"category":kind,"name":p.name,"extension":p.suffix.lower() or "(sin extensión)","mime":mimetypes.guess_type(p.name)[0] or "application/octet-stream","detected_type":actual,"extension_mismatch":mismatch,"size":stat.st_size,"modified_utc":ts,"path":rel,"sha256":digest}
        catalog.append(row)
        if mismatch: mismatches.append(row)
        timeline.append({"timestamp_utc":ts,"type":"filesystem","source":rel,"summary":"Archivo adquirido","citation":{"path":rel,"sha256":digest}})
        if content:
            docs.append({"path":rel,"sha256":digest,"text":content})
            entities["emails"].update(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",content))
            entities["phones"].update(re.findall(r"(?<!\d)(?:\+?\d[\d .()-]{7,}\d)",content))
            entities["urls"].update(re.findall(r"https?://[^\s\"'<>]+",content))
            for m in re.finditer(r"(-?\d{1,2}\.\d{4,8})[, ]+(-?\d{1,3}\.\d{4,8})",content):
                lat,lon=map(float,m.groups())
                if -90<=lat<=90 and -180<=lon<=180: locations.append({"lat":lat,"lon":lon,"source":rel,"sha256":digest})
    # Safe SQLite metadata inventory: immutable/read-only, no copied database is changed.
    sqlite_rows=[]
    for p in files(case):
        if p.suffix.lower() not in {".db",".sqlite",".sqlite3"}: continue
        try:
            con=sqlite3.connect(f"{p.as_uri()}?mode=ro&immutable=1",uri=True); names=[r[0] for r in con.execute("select name from sqlite_master where type='table'")]; con.close()
            sqlite_rows.append({"path":p.relative_to(case).as_posix(),"sha256":sha(p),"tables":names})
        except sqlite3.Error as e: sqlite_rows.append({"path":p.relative_to(case).as_posix(),"error":str(e)})
    # Search/RAG index keeps citations and excerpts, never invents source content.
    db=sqlite3.connect(report/"knowledge.sqlite")
    db.executescript("drop table if exists documents; create virtual table documents using fts5(path,sha256,text); ")
    db.executemany("insert into documents values(?,?,?)",[(d["path"],d["sha256"],d["text"]) for d in docs]); db.commit(); db.close()
    dups=[{"sha256":h,"paths":ps} for h,ps in duplicates.items() if len(ps)>1]
    geo={"type":"FeatureCollection","features":[{"type":"Feature","geometry":{"type":"Point","coordinates":[x["lon"],x["lat"]]},"properties":{"source":x["source"],"sha256":x["sha256"]}} for x in locations]}
    atomic(report/"timeline.json",timeline); atomic(report/"locations.geojson",geo); atomic(report/"duplicates.json",dups)
    atomic(report/"sqlite_inventory.json",sqlite_rows); atomic(report/"entities.json",{k:sorted(v) for k,v in entities.items()})
    graph={"nodes":[],"edges":[]}
    for kind,values in entities.items():
        for value in sorted(values): graph["nodes"].append({"id":hashlib.sha256((kind+value).encode()).hexdigest()[:16],"type":kind,"label":value})
    for d in docs:
        for node in graph["nodes"]:
            if node["label"] in d["text"]: graph["edges"].append({"entity":node["id"],"source":d["path"],"source_sha256":d["sha256"]})
    atomic(report/"relationship_graph.json",graph)
    bookmarks=report/"bookmarks.json"
    if not bookmarks.exists(): atomic(bookmarks,{"schema":"FML-BOOKMARKS-1","items":[]})
    atomic(report/"file_catalog.json",{"generated_utc":utc(),"counts":category_counts,"signature_mismatches":len(mismatches),"files":catalog})
    atomic(report/"disguised_files.json",mismatches)
    visible_catalog=catalog[:5000]
    cards="".join(f"<article data-c='{html.escape(x['category'])}' data-q='{html.escape((x['name']+' '+x['path']+' '+x['extension']).lower())}' onclick=\"preview('../../{quote(x['path'])}')\"><b>{html.escape(x['name'])}</b><span>{html.escape(x['category'])} · {x['size']:,} bytes</span><small>{html.escape(x['path'])}</small><small>Firma real: {html.escape(x['detected_type'])}{' ⚠️ EXTENSIÓN NO COINCIDE' if x['extension_mismatch'] else ''}</small><code>SHA-256 {x['sha256']}</code></article>" for x in visible_catalog)
    buttons="".join(f"<button onclick=\"f('{html.escape(k)}')\">{html.escape(k)} ({v})</button>" for k,v in sorted(category_counts.items()))
    catalog_html=f"""<!doctype html><meta charset='utf-8'><style>:root{{color-scheme:dark}}body{{font:14px -apple-system;background:#091117;color:#e3f2f3;padding:24px}}header{{position:sticky;top:0;background:#091117ee;padding-bottom:12px;z-index:2}}input{{width:95%;padding:11px;background:#13252d;color:white;border:1px solid #385863;border-radius:9px}}button{{margin:4px;padding:7px;border:0;border-radius:8px}}main{{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px}}article{{padding:14px;background:#13252d;border:1px solid #31515d;border-radius:12px;word-break:break-word;cursor:pointer}}span,small,code{{display:block;margin-top:7px}}small{{color:#9bb0b5}}code{{font-size:9px;color:#65eab0}}dialog{{width:90vw;height:85vh;background:#0b151a;border:1px solid #45636c;border-radius:14px}}iframe{{width:100%;height:92%;border:0;background:white}}</style><header><h1>Catálogo universal de evidencia</h1><p>Vista organizada; los originales no se mueven ni se modifican. Mostrando {len(visible_catalog):,} de {len(catalog):,} archivos; el JSON conserva el catálogo completo.</p><input id='q' placeholder='Buscar archivo, ruta o extensión' oninput='f()'><div><button onclick=\"f('')\">TODOS ({len(visible_catalog)})</button>{buttons}</div></header><main>{cards}</main><dialog id='viewer'><button onclick=\"viewer.close()\">Cerrar</button><iframe id='frame' sandbox></iframe></dialog><script>let c='';function f(x){{if(x!==undefined)c=x;let q=document.querySelector('#q').value.toLowerCase();document.querySelectorAll('article').forEach(e=>e.hidden=!!((c&&e.dataset.c!==c)||(q&&!e.dataset.q.includes(q))))}}function preview(u){{frame.src=u;viewer.showModal()}}</script>"""
    (report/"file_catalog.html").write_text(catalog_html,encoding="utf-8"); os.chmod(report/"file_catalog.html",0o600)
    capabilities={
      "physical_image_intake":"authorized examiner-supplied images only; no bypass/exploit",
      "ios":"supports inventory of an examiner-supplied iTunes/Finder backup; encrypted backup requires its lawful password",
      "conversation_reconstruction":"source-preserving SQLite inventory plus existing app decoders",
      "ocr":"local adapter: macOS Vision/Tesseract when installed; original remains immutable",
      "transcription":"local adapter: Whisper-compatible command when installed; original remains immutable",
      "local_rag":"FTS5 evidence-grounded answers with exact path and SHA-256 citations",
      "plugins":"signed descriptor allow-list; each external analyzer runs as a separate process",
      "confirmed_deleted":"never inferred from an ADB-visible residual file alone"
    }
    qc={"status":"PASS" if not mismatches else "REVIEW","files_cataloged":len(catalog),"zero_byte_files":sum(1 for x in catalog if x['size']==0),"signature_mismatches":len(mismatches),"hashes_present":all(bool(x['sha256']) for x in catalog),"required_reports":["file_catalog.json","timeline.json","entities.json","custody_chain.json"]}
    atomic(report/"quality_control.json",qc)
    summary={"schema":"FML-ADVANCED-3.0","created_utc":utc(),"case":str(case),"files":sum(len(v) for v in duplicates.values()),"categories":category_counts,"catalog":"reports/advanced/file_catalog.html","signature_mismatches":len(mismatches),"quality_control":qc,"documents_indexed":len(docs),"timeline_events":len(timeline),"locations":len(locations),"duplicate_groups":len(dups),"sqlite_databases":len(sqlite_rows),"capabilities":capabilities}
    atomic(report/"advanced_summary.json",summary)
    custody=report/"custody_chain.json"; chain=json.loads(custody.read_text()) if custody.exists() else []
    chain.append(event("ADVANCED_ANALYSIS",{"summary_sha256":sha(report/"advanced_summary.json")},chain[-1]["event_hash"] if chain else "")); atomic(custody,chain)
    return summary

def ask(case: Path, query: str) -> dict[str, Any]:
    case=safe_directory(case,"El expediente")
    db=sqlite3.connect(case/"reports"/"advanced"/"knowledge.sqlite"); db.row_factory=sqlite3.Row
    safe=" OR ".join(re.findall(r"[\wáéíóúñÁÉÍÓÚÑ]+",query)) or '""'
    try: rows=db.execute("select path,sha256,snippet(documents,2,'[',']','…',24) excerpt,bm25(documents) rank from documents where documents match ? order by rank limit 12",(safe,)).fetchall()
    except sqlite3.Error: rows=[]
    db.close(); citations=[dict(r) for r in rows]
    return {"question":query,"answer":"Se localizaron %d fuentes relevantes. Revise los extractos; esta respuesta no agrega hechos no presentes en la evidencia."%len(citations),"citations":citations,"model":"local-retrieval-only","generated_utc":utc()}

def compare(a: Path,b: Path) -> dict[str,Any]:
    a=safe_directory(a,"El primer expediente"); b=safe_directory(b,"El segundo expediente")
    def man(root): return {p.relative_to(root).as_posix():sha(p) for p in files(root)}
    x,y=man(a),man(b); return {"added":sorted(y.keys()-x.keys()),"removed":sorted(x.keys()-y.keys()),"modified":sorted(k for k in x.keys()&y.keys() if x[k]!=y[k])}

def portable(case: Path,out: Path) -> dict[str,Any]:
    case=safe_directory(case,"El expediente")
    if out.is_symlink(): raise ValueError("El paquete de salida no puede ser un enlace simbólico")
    out=out.resolve(); package_files=[]
    for candidate in sorted(case.rglob("*")):
        if not candidate.is_file() or candidate.is_symlink(): continue
        relative=candidate.relative_to(case)
        if ".ui_cache" in relative.parts or candidate.suffix in {".partial", ".tmp"}: continue
        if relative.as_posix()=="reports/integrity_verification.json": continue
        package_files.append(candidate)
    manifest=[{"path":p.relative_to(case).as_posix(),"sha256":sha(p),"size":p.stat().st_size} for p in package_files]
    verifier="""#!/usr/bin/env python3
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve();m=json.loads((r/'PORTABLE_MANIFEST.json').read_text());bad=[];declared=set()
for x in m.get('files',[]):
 rel=pathlib.PurePosixPath(str(x.get('path','')))
 if rel.is_absolute() or '..' in rel.parts:bad.append({'path':str(rel),'error':'UNSAFE_PATH'});continue
 p=r.joinpath(*rel.parts);declared.add(rel.as_posix())
 if p.is_symlink() or not p.is_file():bad.append({'path':rel.as_posix(),'actual':'MISSING_OR_SYMLINK'});continue
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 if h.hexdigest()!=x.get('sha256') or p.stat().st_size!=x.get('size'):bad.append({'path':rel.as_posix(),'actual':h.hexdigest(),'size':p.stat().st_size})
actual={p.relative_to(r).as_posix() for p in r.rglob('*') if p.is_file() and not p.is_symlink()}-{'PORTABLE_MANIFEST.json','verify_portable.py'}
extra=sorted(actual-declared);missing=sorted(declared-actual);valid=not bad and not extra and not missing
print(json.dumps({'valid':valid,'failures':bad,'unexpected':extra,'missing':missing,'files_checked':len(declared)},indent=2));raise SystemExit(not valid)
"""
    out.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
        for p in package_files: z.write(p,p.relative_to(case).as_posix())
        z.writestr("PORTABLE_MANIFEST.json",json.dumps({"created_utc":utc(),"files":manifest},indent=2)); z.writestr("verify_portable.py",verifier)
    os.chmod(out,0o600)
    return {"package":str(out),"sha256":sha(out),"files":len(manifest)}

def ios_inventory(backup: Path,out: Path) -> dict[str,Any]:
    backup=safe_directory(backup,"El backup iOS")
    indicators=[x for x in ("Manifest.db","Manifest.plist","Info.plist","Status.plist") if (backup/x).exists()]
    result={"type":"AUTHORIZED_IOS_BACKUP_INTAKE","source":str(backup.resolve()),"recognized":bool(indicators),"indicators":indicators,"files":sum(1 for _ in files(backup)),"limitations":"No password bypass, jailbreak, exploit or deleted/unallocated recovery is performed."}; atomic(out,result); return result

def _pmd_env() -> dict[str,str]:
    env=os.environ.copy(); bundled=Path(__file__).resolve().parent/"python-packages"
    env["PYTHONPATH"]=str(bundled)+(os.pathsep+env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONDONTWRITEBYTECODE"]="1"; return env

def iphone_devices() -> dict[str,Any]:
    proc=subprocess.run([sys.executable,"-m","pymobiledevice3","usbmux","list"],capture_output=True,text=True,env=_pmd_env())
    if proc.returncode: raise RuntimeError(proc.stderr.strip() or "No se pudo consultar usbmux")
    try: devices=json.loads(proc.stdout)
    except json.JSONDecodeError: devices=[]
    return {"connected":len(devices),"devices":devices,"requirements":["iPhone desbloqueado","Cable USB de datos","Pulse Confiar en el iPhone","Espacio libre suficiente en la Mac"]}

def iphone_backup(case: Path, full: bool=True) -> dict[str,Any]:
    case=safe_directory(case,"El expediente")
    for candidate in (case/"evidence",case/"reports",case/"reports"/"advanced",case/"evidence"/"ios_backup"):
        if candidate.is_symlink(): raise ValueError("Las carpetas internas del expediente no pueden ser enlaces simbólicos")
    backup_root=case/"evidence"/"ios_backup"; backup_root.mkdir(parents=True,exist_ok=True); os.chmod(backup_root,0o700)
    reports=case/"reports"/"advanced"; reports.mkdir(parents=True,exist_ok=True)
    checkpoint=reports/"ios_backup_checkpoint.json"
    devices=iphone_devices()
    if devices["connected"]!=1: raise RuntimeError(f"Se requiere exactamente un iPhone USB autorizado; detectados: {devices['connected']}")
    atomic(checkpoint,{"status":"IN_PROGRESS","started_utc":utc(),"destination":str(backup_root),"full":full,"device_count":1})
    cmd=[sys.executable,"-m","pymobiledevice3","backup2","backup"]
    if full: cmd.append("--full")
    cmd.append(str(backup_root))
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,env=_pmd_env())
    assert proc.stdout is not None
    log_path=reports/"ios_backup.log"; lines=0
    try:
        with log_path.open("a",encoding="utf-8",buffering=1) as log:
            log.write(f"\n=== BACKUP SESSION {utc()} ===\n")
            for line in proc.stdout:
                clean=line.rstrip(); log.write(clean+"\n"); print(clean,flush=True); lines+=1
                if lines%50==0:
                    atomic(checkpoint,{"status":"IN_PROGRESS","updated_utc":utc(),"destination":str(backup_root),"full":full,"log_lines":lines,"last_message":clean[-500:]})
        rc=proc.wait()
    except BaseException:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        atomic(checkpoint,{"status":"INTERRUPTED","updated_utc":utc(),"destination":str(backup_root),"log_lines":lines})
        raise
    finally:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    if rc: atomic(checkpoint,{"status":"INTERRUPTED","updated_utc":utc(),"return_code":rc,"destination":str(backup_root)}); raise RuntimeError("El backup se interrumpió; puede reanudarse desde el mismo expediente")
    device_dirs=[p for p in backup_root.iterdir() if p.is_dir()]
    manifests=[p for d in device_dirs for p in (d/"Manifest.db",d/"Manifest.plist",d/"Info.plist") if p.exists()]
    result={"status":"COMPLETE","completed_utc":utc(),"destination":str(backup_root),"device_backups":len(device_dirs),"files":sum(1 for _ in files(backup_root)),"manifests":[{"path":str(p.relative_to(case)),"sha256":sha(p)} for p in manifests],"encrypted_analysis_note":"If Manifest.plist marks the backup encrypted, lawful password is required to decode protected contents."}
    atomic(checkpoint,result); build(case); return result

def disk_list() -> dict[str,Any]:
    proc=subprocess.run(["/usr/sbin/diskutil","list","-plist"],capture_output=True,check=True)
    payload=plistlib.loads(proc.stdout); disks=[]
    for item in payload.get("AllDisksAndPartitions",[]):
        disks.append({"device":item.get("DeviceIdentifier"),"size":item.get("Size"),"partitions":len(item.get("Partitions",[])),"safety":"Select by model/serial/size, unmount, then acquire read-only."})
    return {"disks":disks,"warning":"Never acquire the active system disk from the running OS; use Recovery or another workstation."}

def image_source(source: Path, output: Path, confirm: str, chunk=8*1024*1024) -> dict[str,Any]:
    if source.is_symlink(): raise ValueError("La fuente no puede ser un enlace simbólico")
    if output.is_symlink(): raise ValueError("La salida no puede ser un enlace simbólico")
    source=source.resolve(strict=True); output=output.resolve(); required="READ-ONLY-"+source.name
    if confirm!=required: raise ValueError(f"Confirmation required: {required}")
    if source == output: raise ValueError("La fuente y la salida deben ser archivos distintos")
    if source.as_posix().startswith("/dev/") and not source.name.startswith("rdisk"): raise ValueError("Use the raw /dev/rdisk device after unmounting it")
    output.parent.mkdir(parents=True,exist_ok=True); checkpoint=output.with_suffix(output.suffix+".checkpoint.json")
    if checkpoint.is_symlink(): raise ValueError("El checkpoint no puede ser un enlace simbólico")
    if output.exists() and not output.is_file(): raise ValueError("La salida existente no es un archivo regular")
    offset=output.stat().st_size if output.exists() else 0
    initial=os.stat(source)
    if source.is_file() and offset > initial.st_size: raise ValueError("La copia parcial es mayor que la fuente")
    if offset:
        remaining=offset
        with source.open("rb",buffering=0) as src, output.open("rb",buffering=0) as existing:
            while remaining:
                size=min(chunk,remaining); left=src.read(size); right=existing.read(size)
                if left != right or not left: raise ValueError("La copia parcial no coincide con el prefijo de la fuente; no es seguro reanudar")
                remaining-=len(left)
    mode="ab" if offset else "wb"; copied=offset
    with source.open("rb",buffering=0) as src, output.open(mode) as dst:
        src.seek(offset)
        while True:
            block=src.read(chunk)
            if not block: break
            dst.write(block); dst.flush(); os.fsync(dst.fileno()); copied+=len(block)
            atomic(checkpoint,{"source":str(source),"output":str(output),"bytes_completed":copied,"updated_utc":utc(),"status":"IN_PROGRESS"})
    final=os.stat(source)
    stable=(initial.st_ino,initial.st_size,initial.st_mtime_ns)==(final.st_ino,final.st_size,final.st_mtime_ns)
    if not stable:
        atomic(checkpoint,{"source":str(source),"output":str(output),"bytes_completed":copied,"updated_utc":utc(),"status":"SOURCE_CHANGED"})
        raise RuntimeError("La fuente cambió durante la adquisición; la imagen no se considera final")
    source_hash=sha(source); output_hash=sha(output)
    if source_hash != output_hash:
        atomic(checkpoint,{"source":str(source),"output":str(output),"bytes_completed":copied,"updated_utc":utc(),"status":"HASH_MISMATCH","source_sha256":source_hash,"output_sha256":output_hash})
        raise RuntimeError("El SHA-256 de la imagen no coincide con la fuente")
    result={"source":str(source),"output":str(output),"bytes":copied,"sha256":output_hash,"source_sha256":source_hash,"source_stability":"STABLE","completed_utc":utc(),"mode":"READ_ONLY_SOURCE"}
    atomic(checkpoint,{**result,"status":"COMPLETE"}); os.chmod(output,0o600); return result

def main(argv=None):
    os.umask(0o077)
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True)
    x=s.add_parser("build");x.add_argument("case",type=Path)
    x=s.add_parser("ask");x.add_argument("case",type=Path);x.add_argument("query")
    x=s.add_parser("compare");x.add_argument("first",type=Path);x.add_argument("second",type=Path)
    x=s.add_parser("portable");x.add_argument("case",type=Path);x.add_argument("output",type=Path)
    x=s.add_parser("ios-inventory");x.add_argument("backup",type=Path);x.add_argument("output",type=Path)
    s.add_parser("iphone-devices")
    x=s.add_parser("iphone-backup");x.add_argument("case",type=Path);x.add_argument("--incremental",action="store_true")
    s.add_parser("disk-list")
    x=s.add_parser("disk-image");x.add_argument("source",type=Path);x.add_argument("output",type=Path);x.add_argument("--confirm",required=True)
    a=p.parse_args(argv); result={"build":lambda:build(a.case),"ask":lambda:ask(a.case,a.query),"compare":lambda:compare(a.first,a.second),"portable":lambda:portable(a.case,a.output),"ios-inventory":lambda:ios_inventory(a.backup,a.output),"iphone-devices":iphone_devices,"iphone-backup":lambda:iphone_backup(a.case,not a.incremental),"disk-list":disk_list,"disk-image":lambda:image_source(a.source,a.output,a.confirm)}[a.cmd]()
    print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
