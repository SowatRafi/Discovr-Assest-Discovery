# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller recipe for the portable, single-file Discovr binary.

Build:   pip install -r requirements-dev.txt
         pyinstaller --noconfirm discovr.spec      ->  dist/discovr  (dist\\discovr.exe on Windows)

Notes
- Lazy imports inside functions (cloud SDKs, scapy) are still traced by PyInstaller.
- botocore ships API models for ~400 AWS services; Discovr only calls EC2, STS and SSM
  (plus SSO for `aws sso login` profiles), so the rest are dropped - this is the single
  biggest size (and therefore start-up) saving in the bundle.
- UPX is off: packed executables trip antivirus heuristics, which is fatal for a security
  tool that has to run on client machines.
"""
import re

AWS_SERVICES = {"ec2", "sts", "ssm", "sso", "sso-oidc"}


def keep(dest):
    """Drop botocore service models Discovr never calls; keep everything else."""
    match = re.match(r"botocore[\\/]data[\\/]([^\\/]+)[\\/]", dest)
    return match is None or match.group(1) in AWS_SERVICES


a = Analysis(
    ["discovr/__main__.py"],
    pathex=[],
    binaries=[],
    datas=[("discovr/ui", "discovr/ui")],  # the web UI is served from inside the bundle
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Reached only via scapy's optional ticketer (tkinter), a delayed scapy test helper
    # (unittest) and help() (pydoc) - none are used by Discovr, and Tk alone is several MB.
    excludes=["tkinter", "unittest", "pydoc"],
    noarchive=False,
    optimize=1,
)
a.datas = [entry for entry in a.datas if keep(entry[0])]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="discovr",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
