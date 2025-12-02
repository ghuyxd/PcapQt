# -*- mode: python ; coding: utf-8 -*-
import sys
from PyInstaller.utils.hooks import collect_data_files

# Include tất cả file dữ liệu trong các thư mục
datas = [
    ('icons/*', 'icons'),   # include toàn bộ folder icons
    ('ui_pcapqt.ui', '.'),  # include file .ui
    ('models/*', 'models'),
    ('views/*', 'views'),
    ('threads/*', 'threads'),
    ('utils/*', 'utils'),
]

a = Analysis(
    ['main.py'],
    pathex=['.'],      # thư mục gốc của project
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PcapQt',      # Tên file .exe
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # GUI app, không hiện console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
