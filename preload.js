// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  saveToken: (token) => ipcRenderer.invoke('save-token', token),
  getToken: () => ipcRenderer.invoke('get-token'),
  clearToken: () => ipcRenderer.invoke('clear-token'),
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  minimize: () => ipcRenderer.send('window:minimize'),
  close: () => ipcRenderer.send('window:close'),
  openTelegramAuth: () => ipcRenderer.send('open-telegram-auth'),
  openTogetherFirewall: () => ipcRenderer.invoke('open-together-firewall'),
  updateDiscordPresence: (payload) => ipcRenderer.send('discord:update-presence', payload),
  clearDiscordPresence: () => ipcRenderer.send('discord:clear-presence')
});
