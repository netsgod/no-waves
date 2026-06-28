require('dotenv').config();

const { spawn } = require('child_process');

const rootDir = __dirname;
const electronBinary = require('electron');
const serverUrl = process.env.NOWAVES_SERVER_URL || process.env.NOWAVES_DEFAULT_SERVER_URL || 'http://64.188.73.238:8080';
const skipAuth = process.env.NOWAVES_SKIP_AUTH || '0';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function isServerReady() {
  try {
    const response = await fetch(`${serverUrl}/ping`);
    return response.ok;
  } catch {
    return false;
  }
}

async function ensureServer() {
  if (await isServerReady()) {
    console.log(`Using server at ${serverUrl}`);
    return;
  }

  const timeoutAt = Date.now() + 10000;
  while (Date.now() < timeoutAt) {
    if (await isServerReady()) {
      return;
    }
    await sleep(500);
  }

  throw new Error(`Server is not reachable at ${serverUrl}`);
}

function startElectron() {
  console.log('Starting Electron...');

  const electronProcess = spawn(electronBinary, ['.'], {
    cwd: rootDir,
    detached: true,
    stdio: 'ignore',
    windowsHide: false,
    env: {
      ...process.env,
      NOWAVES_SERVER_URL: serverUrl,
      NOWAVES_SKIP_AUTH: skipAuth
    }
  });

  electronProcess.unref();
}

async function main() {
  await ensureServer();
  startElectron();
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
