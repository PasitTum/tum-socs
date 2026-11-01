// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

const { app, BrowserWindow, ipcMain, Notification, Tray, Menu } = require('electron');
const path = require('path');

let mainWindow = null;
let tray = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'TUM-OpenSIEM — Sovereign Cyber Defense Console',
    backgroundColor: '#030712',
    icon: path.join(__dirname, '../public/favicon.svg'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
    show: false,
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Load URL: try Vite dev server, fallback to local backend or packaged file
  const devUrl = process.env.VITE_DEV_SERVER_URL || 'http://localhost:5173';
  
  if (app.isPackaged) {
    const packagedPath = path.join(__dirname, '../../Tum.Siem.Server/wwwroot/index.html');
    mainWindow.loadFile(packagedPath).catch(() => {
      mainWindow.loadURL('http://localhost:5000');
    });
  } else {
    mainWindow.loadURL(devUrl).catch(() => {
      mainWindow.loadURL('http://localhost:5000');
    });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Handle native OS Notifications
ipcMain.handle('show-notification', async (event, { title, body, isCritical }) => {
  if (Notification.isSupported()) {
    const notif = new Notification({
      title: title || 'TUM-OpenSIEM Security Alert',
      body: body || 'Threat alert detected',
      urgency: isCritical ? 'critical' : 'normal',
      icon: path.join(__dirname, '../public/favicon.svg'),
    });
    notif.show();
    return true;
  }
  return false;
});

// App Lifecycle
app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
