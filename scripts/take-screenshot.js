const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

const PORT = 3000;
const OUTPUT_DIR = path.join(__dirname, '..', 'docs', 'screenshots', 'phase-1');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'signin.png');

// Find chrome or edge path
function getBrowserPath() {
  const possiblePaths = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

async function waitForServer(url, timeoutMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
          if (res.statusCode === 200) resolve();
          else reject();
        });
        req.on('error', reject);
      });
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error('Server timeout');
}

async function run() {
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  const browserPath = getBrowserPath();
  if (!browserPath) {
    console.error('No Chrome or Edge browser found.');
    process.exit(1);
  }

  console.log(`Starting server on port ${PORT}...`);
  const serverProcess = spawn('node', ['src/index.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'inherit'
  });

  try {
    await waitForServer(`http://localhost:${PORT}`);
    console.log('Server is responsive. Capturing screenshot...');

    await new Promise((resolve, reject) => {
      const browser = spawn(
        browserPath,
        [
          '--headless=new',
          '--disable-gpu',
          `--screenshot=${OUTPUT_FILE}`,
          '--window-size=1280,820',
          `http://localhost:${PORT}`
        ],
        { stdio: 'inherit' }
      );

      browser.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`Browser exited with code ${code}`));
      });
    });

    console.log(`Screenshot saved successfully: ${OUTPUT_FILE}`);
  } finally {
    serverProcess.kill('SIGTERM');
  }
}

run().catch((err) => {
  console.error('Screenshot error:', err);
  process.exit(1);
});
