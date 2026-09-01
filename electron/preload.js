const { contextBridge, ipcRenderer } = require('electron');

// Expose a minimal safe API to the renderer (dashboard.html)
contextBridge.exposeInMainWorld('electronAPI', {
  minimize: () => ipcRenderer.send('win:minimize'),
  maximize: () => ipcRenderer.send('win:maximize'),
  close:    () => ipcRenderer.send('win:close'),
  // Report export — returns {ok, path} so the renderer can confirm or explain.
  savePdf:  (name) => ipcRenderer.invoke('report:savePdf', name),
  showFile: (p)    => ipcRenderer.invoke('report:showFile', p),
});
