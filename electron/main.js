// Optional desktop viewer: the OS blanks screenshots and screen recordings of this window.
const { app, BrowserWindow } = require('electron');
const URL_ = process.env.NAMUNA_URL || 'https://design.adihuman.com';
app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 1400, height: 900, backgroundColor: '#f4f2ee',
    webPreferences: { devTools: false, contextIsolation: true, sandbox: true } });
  win.setContentProtection(true);          // macOS + Windows: capture shows black
  win.setMenuBarVisibility(false);
  win.webContents.on('before-input-event', (e, i) => { if (i.key === 'F12' || (i.control && i.shift && i.key.toLowerCase() === 'i')) e.preventDefault(); });
  win.loadURL(URL_);
});
app.on('window-all-closed', () => app.quit());
