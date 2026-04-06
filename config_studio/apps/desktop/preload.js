const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  getEngineUrl: () => ipcRenderer.invoke("get-engine-url"),
  platform: process.platform,
});
