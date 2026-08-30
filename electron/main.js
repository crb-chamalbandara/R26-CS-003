const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// Prevent GPU process conflicts when Playwright launches its own Chromium window
if (app) app.disableHardwareAcceleration();

let mainWindow;
let backendProcess;

// Prefer an explicit PYTHON_PATH override, then the project's .venv so all
// installed packages are available, then the platform's system interpreter.
// C1 and C3 each added their own resolver here; they are folded into this one
// so PYTHON is declared exactly once (two `const PYTHON` bindings in the same
// scope is a SyntaxError and stopped the app booting).
const PYTHON = (() => {
  if (process.env.PYTHON_PATH) return process.env.PYTHON_PATH;
  const venvWin  = path.join(__dirname, '..', '.venv', 'Scripts', 'python.exe');
  const venvUnix = path.join(__dirname, '..', '.venv', 'bin', 'python');
  if (fs.existsSync(venvWin))  return venvWin;
  if (fs.existsSync(venvUnix)) return venvUnix;
  return process.platform === 'win32' ? 'python' : 'python3';
})();
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
    backgroundColor: '#05090f',
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

// ── IPC: save the C1 report as a real PDF ─────────────────────────────────────
// Previously the renderer called window.print(), which raises Electron's print
// dialog — a printer picker with "This app doesn't support print preview" where
// the user expected a file. printToPDF renders the same @media print stylesheet
// straight to a PDF buffer, so the user gets one native Save dialog and a file.
ipcMain.handle('report:savePdf', async (_evt, suggestedName) => {
  if (!mainWindow || mainWindow.isDestroyed()) return { ok: false, reason: 'no window' };
  try {
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: 'Save analysis report',
      defaultPath: suggestedName || 'extension_analysis.pdf',
      filters: [{ name: 'PDF document', extensions: ['pdf'] }],
    });
    if (canceled || !filePath) return { ok: false, reason: 'cancelled' };

    const pdf = await mainWindow.webContents.printToPDF({
      printBackground: true,
      pageSize: 'A4',
      margins: { marginType: 'custom', top: 0.4, bottom: 0.4, left: 0.4, right: 0.4 },
    });
    fs.writeFileSync(filePath, pdf);
    return { ok: true, path: filePath };
  } catch (err) {
    console.error('[Main] PDF export failed:', err);
    return { ok: false, reason: String(err && err.message || err) };
  }
});

// Reveal the saved file in the OS file manager.
ipcMain.handle('report:showFile', async (_evt, filePath) => {
  if (filePath) shell.showItemInFolder(filePath);
});
