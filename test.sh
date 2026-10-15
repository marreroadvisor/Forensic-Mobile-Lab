#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
: "${FML_TEST_PYTHON:=python3}"
cache=$(mktemp -d /private/tmp/fml-tests.XXXXXX)
trap 'rm -rf "$cache"' EXIT
export PYTHONPYCACHEPREFIX="$cache/python-cache"
"$FML_TEST_PYTHON" -m unittest discover -s tests -v
cp ForensicMobileLabApp.swift "$cache/main.swift"
xcrun swiftc -typecheck "$cache/main.swift" ForensicToolkit.swift -module-cache-path "$cache/swift-cache" -framework AppKit -framework WebKit -framework Vision -framework CryptoKit
xcrun swiftc -typecheck ForensicVerifier.swift -module-cache-path "$cache/swift-cache" -framework CryptoKit
