const { contextBridge, ipcRenderer } = require('electron');

// Expose a minimal safe API to the renderer (dashboard.html)
contextBridge.exposeInMainWorld('electronAPI', {
  minimize: () => ipcRenderer.send('win:minimize'),
  maximize: () => ipcRenderer.send('win:maximize'),
  close:    () => ipcRenderer.send('win:close'),
});
