#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
: "${FML_RUNTIME_APP:?Indica la ruta a Forensic Mobile Lab.app de la descarga 3.2 en FML_RUNTIME_APP}"
[[ -d "$FML_RUNTIME_APP/Contents/Resources" ]] || exit 1
stage=$(mktemp -d /private/tmp/fml-build.XXXXXX)
trap 'rm -rf "$stage"' EXIT
app="$stage/Forensic Mobile Lab.app"
res="$app/Contents/Resources"
mkdir -p "$res" "$app/Contents/MacOS" dist
for name in PythonRuntime Python3.framework python-packages python-packages-py39 platform-tools; do
  [[ -d "$FML_RUNTIME_APP/Contents/Resources/$name" ]] || { print "Falta runtime: $name"; exit 1; }
  ditto --norsrc --noextattr "$FML_RUNTIME_APP/Contents/Resources/$name" "$res/$name"
done
cp ForensicMobileLabApp.swift "$stage/main.swift"
cp ForensicToolkit.swift ForensicVerifier.swift "$stage/"
for arch in arm64 x86_64; do
  xcrun swiftc "$stage/main.swift" "$stage/ForensicToolkit.swift" -O -target "$arch-apple-macosx13.0" -module-cache-path "$stage/cache-$arch" -framework AppKit -framework WebKit -framework Vision -framework CryptoKit -o "$stage/app-$arch"
  xcrun swiftc "$stage/ForensicVerifier.swift" -O -target "$arch-apple-macosx13.0" -module-cache-path "$stage/cache-$arch" -framework CryptoKit -o "$stage/verifier-$arch"
done
lipo -create "$stage/app-arm64" "$stage/app-x86_64" -output "$app/Contents/MacOS/ForensicMobileLab"
lipo -create "$stage/verifier-arm64" "$stage/verifier-x86_64" -output "$res/ForensicVerifier"
cp Info.plist "$app/Contents/Info.plist"
cp forensic_mobile_lab.py forensic_advanced.py standalone_whatsapp_app.py ForensicMobileLabApp.swift ForensicToolkit.swift ForensicVerifier.swift README.md GUIA.md DEPENDENCIES.md DEPENDENCY_SOURCES.json PRIVACY.md RELEASE-NOTES-3.2.md SEGURIDAD-Y-VERIFICACION.md PrivacyInfo.xcprivacy ForensicMobileLab.icns LICENSE "$res/"
ditto --norsrc --noextattr tests "$res/tests"
ditto --norsrc --noextattr licenses "$res/licenses"
python3 - "$app" <<'PYCLEAN'
import pathlib,shutil,sys
p=pathlib.Path(sys.argv[1])
for x in p.rglob('__pycache__'):
 if x.is_dir(): shutil.rmtree(x)
for x in p.rglob('*.pyc'): x.unlink()
PYCLEAN
chmod 755 "$app/Contents/MacOS/ForensicMobileLab" "$res/ForensicVerifier" "$res/platform-tools/adb"
codesign --force --deep --options runtime --timestamp=none --sign - "$app"
codesign --verify --deep --strict "$app"
ditto -c -k --norsrc --noextattr --keepParent "$app" dist/Forensic-Mobile-Lab-3.2.0-macOS-universal.zip
print 'Creado dist/Forensic-Mobile-Lab-3.2.0-macOS-universal.zip'
