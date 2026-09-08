const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

// Prevent GPU process conflicts when Playwright launches its own Chromium window
if (app) app.disableHardwareAcceleration();

let mainWindow;
let backendProcess;

const VENV_PYTHON = path.join(__dirname, '..', '.venv', 'Scripts', 'python.exe');
const PYTHON = process.env.PYTHON_PATH
  || (require('fs').existsSync(VENV_PYTHON) ? VENV_PYTHON : 'python');
const BACKEND_DIR = path.join(__dirname, '..');   // project root — uvicorn runs from here
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const BACKEND_PORT = 8765;

// ── Start FastAPI backend ─────────────────────────────────────────────────────
function startBackend() {
  console.log('[Main] Starting Python/FastAPI backend...');
  backendProcess = spawn(
    PYTHON,
    ['-m', 'uvicorn', 'core.main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT), '--log-level', 'info'],
    {
      cwd: BACKEND_DIR,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Force Python's stdout/stderr to encode as UTF-8 regardless of the
      // Windows console's active codepage. Without this, Python falls back
      // to the system locale encoding (often cp1252) when its output is
      // piped rather than attached to a real console, so any non-ASCII
      // character it prints (e.g. an em dash in a log line) is encoded as
      // one thing while the line below decodes the bytes as UTF-8 --
      // producing garbled text like "No c2_fusion.pkl <20><><1D> using
      // weighted-sum fusion" instead of a clean line. This does not change
      // any Python source or logic, only how its output bytes are encoded.
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' },
    }
  );

  // Prefix every line, not just the first line of each data chunk -- uvicorn
  // often flushes several log lines at once, and a single '[Backend] ' + d
  // prepend only tags whichever line happened to be first in that chunk,
  // leaving the rest looking like they came from Electron itself.
  const prefixLines = (buf) =>
    buf.toString('utf-8').replace(/\r?\n(?!$)/g, '\n[Backend] ');
  backendProcess.stdout.on('data', d => process.stdout.write('[Backend] ' + prefixLines(d)));
  backendProcess.stderr.on('data', d => process.stderr.write('[Backend] ' + prefixLines(d)));
  backendProcess.on('exit', code => console.log('[Backend] Process exited:', code));
  backendProcess.on('error', err => console.error('[Backend] Failed to start:', err.message));
}

// ── Create main window ────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#0a0e1a',
    show: false,
    title: 'WebSentinel',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,       // enable <webview> in renderer
      webSecurity: false,     // allow fetch to localhost:8000
    },
  });

  mainWindow.loadFile(path.join(FRONTEND_DIR, 'dashboard.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // Re-paint if another Chromium window (Playwright) causes a blackout
  mainWindow.on('blur', () => {
    setTimeout(() => { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.invalidate(); }, 300);
  });

  // Open DevTools with --dev flag
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  startBackend();
  // Give the backend ~1.5s to start uvicorn before opening the window
  setTimeout(createWindow, 1500);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  // On macOS the app is allowed to keep running with no windows; only
  // quit on other platforms. Don't kill the backend here — `activate`
  // can re-open the window and would otherwise find a dead backend.
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill('SIGTERM');
    console.log('[Main] Backend killed');
  }
});

// ── IPC: native window controls ───────────────────────────────────────────────
ipcMain.on('win:minimize', () => mainWindow?.minimize());
ipcMain.on('win:maximize', () => {
  mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
});
ipcMain.on('win:close', () => mainWindow?.close());
