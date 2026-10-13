# PyInstaller spec for the C1 guest runtime (onedir build).
# Build from the repo root:  pyinstaller packaging/c1_guest.spec --noconfirm
#
# What this is: the program that runs INSIDE the disposable Windows Sandbox virtual machine.
#
# On a development machine the VM is lent the host's own Python and site-packages. An installed copy
# of WebSentinel has neither: its backend is a frozen program with no python.exe to share. So the
# installer ships this folder instead. It holds Python, Playwright (with its driver) and the
# observation code, and nothing else. The backend maps it read-only into the VM and the .wsb logon
# command starts c1-guest.exe (see core/c1/isolation/windows_sandbox.py).
#
# The two source files are copied at build time rather than kept as second copies in the repo, so the
# VM always runs exactly the code the host analyses with:
#   core/c1/isolation/guest_agent.py  the entry point
#   core/c1/sandbox.py                the observation code, under the name the agent imports it by
import os
import shutil
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
SRC = os.path.join(ROOT, 'build', 'c1_guest_src')
os.makedirs(SRC, exist_ok=True)
shutil.copy2(os.path.join(ROOT, 'core', 'c1', 'isolation', 'guest_agent.py'), os.path.join(SRC, 'guest_agent.py'))
shutil.copy2(os.path.join(ROOT, 'core', 'c1', 'sandbox.py'), os.path.join(SRC, 'sandbox_observer.py'))

# Playwright ships a Node driver and data files PyInstaller cannot discover by itself.
datas, binaries, hiddenimports = collect_all('playwright')
hiddenimports += ['sandbox_observer']      # imported by name inside guest_agent.main()

a = Analysis(
    [os.path.join(SRC, 'guest_agent.py')],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    # The guest needs the standard library and Playwright only. Keeping the analysis stack out is what
    # keeps this folder small (it is shipped inside every installer).
    excludes=['tkinter', 'matplotlib', 'IPython', 'notebook', 'numpy', 'pandas', 'scipy', 'sklearn',
              'xgboost', 'fastapi', 'uvicorn', 'PIL', 'lxml', 'cryptography'],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='c1-guest',
    console=True,          # the bootstrap redirects its output into the run's agent.log
)
coll = COLLECT(exe, a.binaries, a.datas, name='c1_guest')
