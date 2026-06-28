require('dotenv').config();

const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const { execFile } = require('child_process');
const { autoUpdater } = require('electron-updater');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const RELEASE_SERVER_URL = 'http://64.188.73.238:8080';
const DEFAULT_SERVER_URL = process.env.NOWAVES_DEFAULT_SERVER_URL || RELEASE_SERVER_URL;
const SERVER_URL = app.isPackaged
    ? RELEASE_SERVER_URL
    : (process.env.NOWAVES_SERVER_URL || DEFAULT_SERVER_URL);
const SKIP_AUTH = !app.isPackaged && process.env.NOWAVES_SKIP_AUTH === '1';
const DEV_PROXY_URL = process.env.NOWAVES_PROXY_URL;
const UPDATE_REPO_OWNER = 'netsgod';
const UPDATE_REPO_NAME = 'no-waves';
const UPDATE_POLL_INTERVAL_MS = 6 * 60 * 60 * 1000;
const SESSION_REVALIDATE_INTERVAL_MS = 15 * 60 * 1000;
let embeddedServerModule = null;
let mainWindow = null;
let updateCheckInProgress = false;
let updatePromptVisible = false;
let sessionRevalidateTimer = null;
let updatePollTimer = null;
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
    app.quit();
    process.exit(0);
} else {
    app.on('second-instance', () => {
        const win = BrowserWindow.getAllWindows()[0];
        if (win) {
            if (win.isMinimized()) win.restore();
            win.focus();
        }
    });
}

function shouldUseEmbeddedServer(targetUrl) {
    try {
        const parsed = new URL(targetUrl);
        return ['127.0.0.1', 'localhost', '0.0.0.0'].includes(parsed.hostname);
    } catch {
        return false;
    }
}

function execFileAsync(filePath, args, options = {}) {
    return new Promise((resolve, reject) => {
        execFile(filePath, args, {
            windowsHide: true,
            ...options
        }, (error, stdout, stderr) => {
            if (error) {
                error.stdout = stdout;
                error.stderr = stderr;
                reject(error);
                return;
            }

            resolve({ stdout, stderr });
        });
    });
}

async function execFileQuiet(filePath, args, options = {}) {
    try {
        await execFileAsync(filePath, args, options);
        return true;
    } catch {
        return false;
    }
}

function escapePowerShellString(value) {
    return String(value || '').replace(/'/g, "''");
}

function encodePowerShellCommand(command) {
    return Buffer.from(String(command || ''), 'utf16le').toString('base64');
}

function getElevatePath() {
    const candidates = [
        path.join(process.resourcesPath || '', 'elevate.exe'),
        path.join(__dirname, 'dist', 'win-unpacked', 'resources', 'elevate.exe')
    ];

    return candidates.find((candidate) => candidate && fs.existsSync(candidate)) || '';
}

async function runNetshFirewallRules(elevated = false) {
    const appPath = process.execPath;
    const oldPortRuleName = 'NoWaves Together 8080';
    const oldProgramRuleName = 'NoWaves Together App';
    const portRuleName = 'NoWavesTogether8080';
    const programRuleName = 'NoWavesTogetherApp';
    const baseRunner = elevated ? getElevatePath() : 'netsh';

    if (elevated && !baseRunner) {
        throw new Error('elevate.exe was not found');
    }

    const runNetsh = (args, strict = true) => {
        const runnerArgs = elevated
            ? ['-wait', 'netsh', ...args]
            : args;
        return strict
            ? execFileAsync(baseRunner, runnerArgs)
            : execFileQuiet(baseRunner, runnerArgs);
    };

    await runNetsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${oldPortRuleName}`], false);
    await runNetsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${oldProgramRuleName}`], false);
    await runNetsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${portRuleName}`], false);
    await runNetsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${programRuleName}`], false);

    await runNetsh([
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=${portRuleName}`,
        'dir=in',
        'action=allow',
        'protocol=TCP',
        'localport=8080',
        'profile=any'
    ]);

    await runNetsh([
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=${programRuleName}`,
        'dir=in',
        'action=allow',
        `program=${appPath}`,
        'enable=yes',
        'profile=any'
    ]);
}

async function openFirewallWithPowerShellFallback() {
    const portRuleName = 'NoWavesTogether8080';
    const programRuleName = 'NoWavesTogetherApp';
    const innerCommand = [
        "$ErrorActionPreference = 'Stop'",
        `$portRuleName = '${escapePowerShellString(portRuleName)}'`,
        `$programRuleName = '${escapePowerShellString(programRuleName)}'`,
        `$programPath = '${escapePowerShellString(process.execPath)}'`,
        "& netsh advfirewall firewall delete rule name=\"$portRuleName\" | Out-Null",
        "& netsh advfirewall firewall add rule name=\"$portRuleName\" dir=in action=allow protocol=TCP localport=8080 profile=any | Out-Null",
        "& netsh advfirewall firewall delete rule name=\"$programRuleName\" | Out-Null",
        "if (Test-Path $programPath) {",
        "    & netsh advfirewall firewall add rule name=\"$programRuleName\" dir=in action=allow \"program=$programPath\" enable=yes profile=any | Out-Null",
        "}"
    ].join('\r\n');
    const outerCommand = [
        "$ErrorActionPreference = 'Stop'",
        `$encodedInner = '${encodePowerShellCommand(innerCommand)}'`,
        "$process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand', $encodedInner) -Verb RunAs -WindowStyle Hidden -Wait -PassThru",
        'exit $process.ExitCode'
    ].join('\r\n');

    await execFileAsync('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        encodePowerShellCommand(outerCommand)
    ]);
}

async function openTogetherFirewall() {
    try {
        await runNetshFirewallRules(false);
        return true;
    } catch {}

    try {
        await runNetshFirewallRules(true);
        return true;
    } catch {}

    await openFirewallWithPowerShellFallback();
    return true;
}

async function isServerReady(targetUrl) {
    return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };

        try {
            const url = new URL(`${targetUrl.replace(/\/$/, '')}/ping`);
            const transport = url.protocol === 'https:' ? https : http;
            const request = transport.request(url, { method: 'GET' }, (response) => {
                response.resume();
                finish(response.statusCode >= 200 && response.statusCode < 300);
            });

            request.setTimeout(1500, () => {
                request.destroy();
                finish(false);
            });

            request.on('error', () => finish(false));
            request.end();
        } catch {
            finish(false);
        }
    });
}

function getTokenPath() {
    return path.join(app.getPath('userData'), 'token.txt');
}

function readSavedToken() {
    const tokenPath = getTokenPath();
    if (!fs.existsSync(tokenPath)) return '';
    return String(fs.readFileSync(tokenPath, 'utf8') || '').trim();
}

function clearSavedToken() {
    const tokenPath = getTokenPath();
    if (fs.existsSync(tokenPath)) {
        fs.unlinkSync(tokenPath);
    }
}

async function validateSavedToken(targetUrl, token) {
    if (!token) return false;

    return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };

        try {
            const url = new URL(`${targetUrl.replace(/\/$/, '')}/api/auth/session`);
            const transport = url.protocol === 'https:' ? https : http;
            const request = transport.request(url, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${token}`
                }
            }, (response) => {
                let body = '';

                response.on('data', (chunk) => {
                    body += String(chunk || '');
                });

                response.on('end', () => {
                    if (response.statusCode !== 200) {
                        finish(false);
                        return;
                    }

                    try {
                        const payload = JSON.parse(body || '{}');
                        finish(Boolean(payload?.ok));
                    } catch {
                        finish(false);
                    }
                });
            });

            request.setTimeout(3000, () => {
                request.destroy();
                finish(false);
            });

            request.on('error', () => finish(false));
            request.end();
        } catch {
            finish(false);
        }
    });
}

function getActiveWindow() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        return mainWindow;
    }

    return BrowserWindow.getAllWindows()[0] || null;
}

async function showMessageBoxSafe(options) {
    const win = getActiveWindow();
    return dialog.showMessageBox(win || undefined, options);
}

function configureAutoUpdater() {
    if (!app.isPackaged || process.platform !== 'win32') {
        return;
    }

    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = true;

    autoUpdater.on('update-available', async (info) => {
        try {
            await showMessageBoxSafe({
                type: 'info',
                title: 'Обновление no waves',
                message: `Найдена новая версия ${info.version}.`,
                detail: `Обновление будет скачано автоматически из GitHub Releases репозитория ${UPDATE_REPO_OWNER}/${UPDATE_REPO_NAME}.`,
                buttons: ['Ок'],
                defaultId: 0
            });
        } catch {}
    });

    autoUpdater.on('update-downloaded', async (info) => {
        if (updatePromptVisible) return;
        updatePromptVisible = true;

        try {
            const result = await showMessageBoxSafe({
                type: 'info',
                title: 'Обновление готово',
                message: `Версия ${info.version} уже скачана.`,
                detail: 'Перезапусти no waves сейчас, чтобы установить обновление.',
                buttons: ['Перезапустить сейчас', 'Позже'],
                defaultId: 0,
                cancelId: 1
            });

            if (result.response === 0) {
                setImmediate(() => autoUpdater.quitAndInstall(false, true));
            }
        } catch (error) {
            console.error('Failed to show update dialog:', error);
        } finally {
            updatePromptVisible = false;
        }
    });

    autoUpdater.on('error', (error) => {
        console.error('Auto update failed:', error);
    });
}

async function checkForAppUpdates({ silent = true } = {}) {
    if (!app.isPackaged || process.platform !== 'win32' || updateCheckInProgress) {
        return false;
    }

    updateCheckInProgress = true;

    try {
        await autoUpdater.checkForUpdates();
        return true;
    } catch (error) {
        console.error('Failed to check for updates:', error);

        if (!silent) {
            await showMessageBoxSafe({
                type: 'error',
                title: 'Обновление no waves',
                message: 'Не удалось проверить обновления.',
                detail: error.message || 'GitHub Releases недоступен.'
            }).catch(() => {});
        }

        return false;
    } finally {
        updateCheckInProgress = false;
    }
}

function startAutoUpdatePolling() {
    if (!app.isPackaged || process.platform !== 'win32') {
        return;
    }

    clearInterval(updatePollTimer);
    updatePollTimer = setInterval(() => {
        checkForAppUpdates({ silent: true }).catch(() => {});
    }, UPDATE_POLL_INTERVAL_MS);

    setTimeout(() => {
        checkForAppUpdates({ silent: true }).catch(() => {});
    }, 12_000);
}

function startSessionRevalidation() {
    clearInterval(sessionRevalidateTimer);

    sessionRevalidateTimer = setInterval(async () => {
        const token = readSavedToken();
        if (!token) return;

        const stillValid = await validateSavedToken(SERVER_URL, token);
        if (stillValid) return;

        clearSavedToken();

        const win = getActiveWindow();
        if (win && !win.isDestroyed()) {
            await win.loadURL(`${SERVER_URL}/register.html`).catch(() => {});
        }

        await showMessageBoxSafe({
            type: 'warning',
            title: 'Сессия завершена',
            message: 'Сервер отозвал текущий доступ.',
            detail: 'Войди заново через ключ, чтобы продолжить пользоваться no waves.'
        }).catch(() => {});
    }, SESSION_REVALIDATE_INTERVAL_MS);
}

async function ensureEmbeddedServer() {
    if (!shouldUseEmbeddedServer(SERVER_URL)) return;
    if (await isServerReady(SERVER_URL)) return;

    const embeddedServerPath = path.join(__dirname, 'auth-server', 'authServer.js');
    if (!fs.existsSync(embeddedServerPath)) {
        throw new Error('Embedded server is not included in this public build.');
    }

    const parsed = new URL(SERVER_URL);
    const port = Number(parsed.port || 8080);
    const userDataPath = app.getPath('userData');
    fs.mkdirSync(userDataPath, { recursive: true });
    process.env.NOWAVES_USER_DATA_DIR = userDataPath;
    process.env.NOWAVES_DB_PATH = path.join(userDataPath, 'users.sqlite');
    embeddedServerModule = require(embeddedServerPath);
    try {
        await embeddedServerModule.startServer({
            port,
            host: '0.0.0.0'
        });
    } catch (error) {
        if (error && error.code === 'EADDRINUSE' && await isServerReady(SERVER_URL)) {
            return;
        }
        throw error;
    }
}

async function createWindow() {
    const win = new BrowserWindow({
        width: 1075,
        height: 755,
        title: 'no waves',
        frame: false,
        resizable: true,
        maximizable: false,
        minimizable: true,
        minWidth: 900,
        minHeight: 650,
        maxWidth: 1600,
        maxHeight: 1200,
        icon: path.join(__dirname, 'icon.ico'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: false
        }
    });

    mainWindow = win;

    if (!app.isPackaged && DEV_PROXY_URL) {
        win.webContents.session.setProxy({
            proxyRules: DEV_PROXY_URL
        });
    }

    win.removeMenu();

    const savedToken = readSavedToken();
    const hasValidToken = await validateSavedToken(SERVER_URL, savedToken);
    if (!hasValidToken && savedToken) {
        clearSavedToken();
    }

    if (SKIP_AUTH || hasValidToken) {
        win.loadURL(`${SERVER_URL}/index.html`);
    } else {
        win.loadURL(`${SERVER_URL}/register.html`);
    }

    ipcMain.handle('save-token', async (event, newToken) => {
        fs.writeFileSync(getTokenPath(), newToken, 'utf8');
        return true;
    });
    ipcMain.handle('get-token', async () => {
        return readSavedToken();
    });
    ipcMain.handle('clear-token', async () => {
        clearSavedToken();
        return true;
    });
    ipcMain.handle('open-together-firewall', async () => {
        try {
            await openTogetherFirewall();
            return { ok: true };
        } catch (error) {
            return {
                ok: false,
                message: 'Could not open port 8080 automatically. Start no waves as administrator and create the room again.'
            };
        }
    });
    ipcMain.handle('check-for-updates', async () => {
        const ok = await checkForAppUpdates({ silent: false });
        return { ok };
    });

    ipcMain.on('open-telegram-auth', () => {
        const oauthUrl =
            `https://oauth.telegram.org/auth?bot_id=8363131093&origin=${encodeURIComponent(SERVER_URL)}&request_access=write&embed=0`;
        shell.openExternal(oauthUrl);
    });

    ipcMain.on('window:minimize', () => win.minimize());
    ipcMain.on('window:close', () => win.close());

    win.on('closed', () => {
        if (mainWindow === win) {
            mainWindow = null;
        }
    });
}

app.whenReady().then(async () => {
    configureAutoUpdater();
    await ensureEmbeddedServer();
    await createWindow();
    startSessionRevalidation();
    startAutoUpdatePolling();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
    const win = BrowserWindow.getAllWindows()[0];
    if (win) win.focus();
});

app.on('before-quit', () => {
    clearInterval(sessionRevalidateTimer);
    clearInterval(updatePollTimer);
    if (!embeddedServerModule || typeof embeddedServerModule.stopServer !== 'function') return;
    embeddedServerModule.stopServer().catch(() => {});
});
