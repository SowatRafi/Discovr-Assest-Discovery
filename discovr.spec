# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller recipe for the ready-to-run USB folder and macOS app bundle.

Build:   pip install -r requirements-dev.txt
         pyinstaller --noconfirm discovr.spec      ->  dist/Discovr (macOS: dist/Discovr.app)

Notes
- Lazy imports inside functions (cloud SDKs) are still traced by PyInstaller.
- botocore ships API models for ~400 AWS services; Discovr only calls EC2, STS and SSM
  (plus SSO for `aws sso login` profiles), so the rest are dropped - this is the single
  biggest size (and therefore start-up) saving in the bundle.
- UPX is off: packed executables trip antivirus heuristics, which is fatal for a security
  tool that has to run on client machines.
"""
import re
import runpy
import sys
from pathlib import Path

notices = runpy.run_path(str(Path(SPECPATH) / "scripts" / "build_notices.py"))["collect_notices"](SPECPATH)

AWS_SERVICES = {"ec2", "sts", "ssm", "sso", "sso-oidc"}
MAC_APP = sys.platform == "darwin"


def keep(dest):
    """Drop botocore service models Discovr never calls; keep everything else."""
    match = re.match(r"botocore[\\/]data[\\/]([^\\/]+)[\\/]", dest)
    return match is None or match.group(1) in AWS_SERVICES


a = Analysis(
    ["discovr/desktop.py"],
    pathex=[],
    binaries=[],
    datas=[("discovr/ui", "discovr/ui"), (str(notices), "discovr")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Raw packet capture is intentionally absent from the install-free USB product.
    excludes=["tkinter", "unittest", "pydoc", "scapy"],
    noarchive=False,
    optimize=1,
)
a.datas = [entry for entry in a.datas if keep(entry[0])]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries if MAC_APP else [],
    a.datas if MAC_APP else [],
    [],
    exclude_binaries=not MAC_APP,
    name="Discovr",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Windows/Linux load libraries in place. A one-executable Mac app avoids framework
# symlinks that cannot be copied to FAT/exFAT; it unpacks to the Mac's own temp disk.
if MAC_APP:
    app = BUNDLE(exe, name="Discovr.app", bundle_identifier="org.discovr.desktop",
                 info_plist={"CFBundleName": "Discovr", "CFBundleShortVersionString": "2.1.0",
                             "CFBundleVersion": "2.1.0", "LSUIElement": True,
                             "NSHighResolutionCapable": True})
else:
    folder = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="Discovr")
