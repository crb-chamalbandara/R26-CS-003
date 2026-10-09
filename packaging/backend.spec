# PyInstaller spec for the WebSentinel backend (onedir build).
# Build from the repo root:  pyinstaller packaging/backend.spec --noconfirm
#
# Data files keep the same relative layout as the repo so the backend's
# `dirname(__file__)/../..` lookups keep working inside the frozen app.
import os
from PyInstaller.utils.hooks import collect_all, collect_data_files

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))

datas, binaries, hiddenimports = [], [], []

# Repo data the backend reads at runtime (only bundled if present at build time).
for rel in [
    'models', 'data',
    os.path.join('core', 'c1', 'models'),
    os.path.join('core', 'c1', 'data'),
    os.path.join('core', 'c1', 'test_malicious_ext'),
    os.path.join('test', 'C2', 'pages'),
    os.path.join('test', 'C3'),
]:
    src = os.path.join(ROOT, rel)
    if os.path.isdir(src):
        datas.append((src, rel))

# Packages that ship data files / native libs PyInstaller can't discover itself.
for pkg in ['sklearn', 'xgboost', 'tldextract', 'imagehash', 'playwright', 'uvicorn', 'pandas']:
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

hiddenimports += [
    'uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan.on',
    'multipart', 'sklearn.utils._typedefs', 'sklearn.neighbors._partition_nodes',
]

a = Analysis(
    [os.path.join(ROOT, 'core', 'server_entry.py')],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=['tkinter', 'matplotlib', 'IPython', 'notebook'],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='websentinel-backend',
    console=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name='backend')
