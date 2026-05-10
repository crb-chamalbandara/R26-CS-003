const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

// Prevent GPU process conflicts when Playwright launches its own Chromium window
app.disableHardwareAcceleration();

let mainWindow;
let backendProcess;

const PYTHON = process.env.PYTHON_PATH || 'C:\\Python312\\python.exe';
const BACKEND_DIR = path.join(__dirname, '..');   // project root — uvicorn runs from here
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const BACKEND_PORT = 8765;

// ── Start FastAPI backend ─────────────────────────────────────────────────────
function startBackend() {
  console.log('[Main] Starting Python/FastAPI backend...');
  backendProcess = spawn(
    PYTHON,
    ['-m', 'uvicorn', 'core.main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT), '--log-level', 'info'],
    { cwd: BACKEND_DIR, stdio: ['ignore', 'pipe', 'pipe'] }
  );

  backendProcess.stdout.on('data', d => process.stdout.write('[Backend] ' + d));
  backendProcess.stderr.on('data', d => process.stderr.write('[Backend] ' + d));
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
