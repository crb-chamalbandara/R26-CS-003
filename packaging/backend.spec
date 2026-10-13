# PyInstaller spec for the WebSentinel backend (onedir build).
# Build from the repo root:  pyinstaller packaging/backend.spec --noconfirm
#
# Data files keep the same relative layout as the repo so the backend's
# `dirname(__file__)/../..` lookups keep working inside the frozen app.
import os
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))

datas, binaries, hiddenimports = [], [], []

# Repo data the backend reads at runtime (only bundled if present at build time).
for rel in [
    'models', 'data',   # root models/ now also holds the C1 pkl files
    os.path.join('core', 'c1', 'data'),
    os.path.join('core', 'c1', 'test_malicious_ext'),
    os.path.join('test', 'C2', 'pages'),
    os.path.join('test', 'C3'),
]:
    src = os.path.join(ROOT, rel)
    if os.path.isdir(src):
        datas.append((src, rel))

# C2 fusion tuning from the dev settings.json (gitignored; written by scripts/tune_fusion.py). Only the
# allow-listed tuning keys are shipped -- never API keys, the ngrok token or the whitelist.
import json
_TUNED_KEYS = ['weights', 'verdict_suspicious', 'verdict_phishing', 'warn_threshold', 'block_threshold']
_BUILTIN_WEIGHTS = {'L1': 0.15, 'L2': 0.25, 'L3': 0.15, 'L4': 0.10, 'L5': 0.20, 'L6': 0.15}
_dev_settings = os.path.join(ROOT, 'core', 'settings.json')
_tuned = {}
if os.path.isfile(_dev_settings):
    try:
        with open(_dev_settings, encoding='utf-8') as fh:
            _all = json.load(fh)
        _tuned = {k: _all[k] for k in _TUNED_KEYS if k in _all}
    except (OSError, ValueError) as exc:
        print(f'[backend.spec] WARNING: could not read core/settings.json: {exc}')
if not _tuned:
    print('[backend.spec] WARNING: no tuned C2 fusion settings found; the app ships the built-in weights')
else:
    if _tuned.get('weights') == _BUILTIN_WEIGHTS:
        print('[backend.spec] WARNING: core/settings.json weights equal the built-in defaults (not tuned)')
    _tuned_out = os.path.join(ROOT, 'build', 'c2_tuned_defaults.json')
    os.makedirs(os.path.dirname(_tuned_out), exist_ok=True)
    with open(_tuned_out, 'w', encoding='utf-8') as fh:
        json.dump(_tuned, fh, indent=2)
    datas.append((_tuned_out, 'core'))
    print(f'[backend.spec] Shipping tuned C2 fusion settings: {_tuned}')

# Packages that ship data files / native libs PyInstaller can't discover itself.
for pkg in ['sklearn', 'xgboost', 'tldextract', 'imagehash', 'playwright', 'uvicorn', 'pandas',
            'bs4', 'lxml']:   # C2 L1 asks bs4 for the "lxml" parser by name; PyInstaller can't see that
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

# anyio picks its backend with importlib.import_module('anyio._backends._asyncio'), which PyInstaller
# cannot see. Without it every StreamingResponse (the Live Test Runner stream) fails with HTTP 500.
hiddenimports += collect_submodules('anyio') + ['anyio._backends._asyncio']

# httpx (C3 threat-intel lookups) verifies HTTPS with certifi's CA bundle; make sure it is in the frozen app.
datas += collect_data_files('certifi')
hiddenimports += ['certifi']

hiddenimports += [
    'uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan.on',
    'unittest', 'unittest.mock', 'argparse', 'http.server', 'runpy',
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
