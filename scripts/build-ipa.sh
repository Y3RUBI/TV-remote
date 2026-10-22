#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -d MiBoxRemote.xcodeproj ]; then xcodegen generate; fi
xcodebuild -project MiBoxRemote.xcodeproj -scheme MiBoxRemote \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath build/DerivedData CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
mkdir -p build/package/Payload
ditto build/DerivedData/Build/Products/Release-iphoneos/MiBoxRemote.app build/package/Payload/MiBoxRemote.app
(cd build/package && /usr/bin/zip -qr ../MiBoxRemote-unsigned.ipa Payload)
python3 - <<'PY'
import zipfile, plistlib
with zipfile.ZipFile('build/MiBoxRemote-unsigned.ipa') as z:
    info = plistlib.loads(z.read('Payload/MiBoxRemote.app/Info.plist'))
    assert info['CFBundleIdentifier'] == 'app.miboxremote.iphone'
    assert 'iphoneos' in info['CFBundleSupportedPlatforms']
    assert 'Payload/MiBoxRemote.app/MiBoxRemote' in z.namelist()
print('IPA package verified. Apple signing is required before installation.')
PY
