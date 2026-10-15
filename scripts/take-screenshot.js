const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

const PORT = 3000;
const PHASE2_DIR = path.join(__dirname, '..', 'docs', 'screenshots', 'phase-2');

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

async function captureUrl(browserPath, url, outputFile) {
  await new Promise((resolve, reject) => {
    const browser = spawn(
      browserPath,
      [
        '--headless=new',
        '--disable-gpu',
        `--screenshot=${outputFile}`,
        '--window-size=1280,1400',
        url
      ],
      { stdio: 'inherit' }
    );

    browser.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Browser exited with code ${code}`));
    });
  });
  console.log(`Saved screenshot: ${outputFile}`);
}

const PHASE4_DIR = path.join(__dirname, '..', 'docs', 'screenshots', 'phase-4');
const PHASE5_DIR = path.join(__dirname, '..', 'docs', 'screenshots', 'phase-5');
const PHASE6_DIR = path.join(__dirname, '..', 'docs', 'screenshots', 'phase-6');

async function run() {
  if (!fs.existsSync(PHASE2_DIR)) {
    fs.mkdirSync(PHASE2_DIR, { recursive: true });
  }
  if (!fs.existsSync(PHASE4_DIR)) {
    fs.mkdirSync(PHASE4_DIR, { recursive: true });
  }
  if (!fs.existsSync(PHASE5_DIR)) {
    fs.mkdirSync(PHASE5_DIR, { recursive: true });
  }
  if (!fs.existsSync(PHASE6_DIR)) {
    fs.mkdirSync(PHASE6_DIR, { recursive: true });
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
    console.log('Server is responsive. Capturing screenshots...');

    // Phase 2 screenshots
    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=mfa-verify`,
      path.join(PHASE2_DIR, 'mfa-verify.png')
    );

    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=mfa-setup`,
      path.join(PHASE2_DIR, 'mfa-setup.png')
    );

    // Phase 4 screenshots
    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=vault`,
      path.join(PHASE4_DIR, 'vault-items.png')
    );

    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=vault-reveal`,
      path.join(PHASE4_DIR, 'vault-reveal.png')
    );

    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=vault-versions`,
      path.join(PHASE4_DIR, 'vault-versions.png')
    );

    // Phase 5 screenshots
    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=files`,
      path.join(PHASE5_DIR, 'files-vault.png')
    );

    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=files-encrypting`,
      path.join(PHASE5_DIR, 'files-encrypting.png')
    );

    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=files-verified`,
      path.join(PHASE5_DIR, 'files-verified.png')
    );

    // Phase 6 screenshots
    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=sessions`,
      path.join(PHASE6_DIR, 'sessions.png')
    );

    await captureUrl(
      browserPath,
      `http://localhost:${PORT}/?view=audit`,
      path.join(PHASE6_DIR, 'audit-trail.png')
    );

    console.log('All screenshots successfully captured!');
  } finally {
    serverProcess.kill('SIGTERM');
  }
}

run().catch((err) => {
  console.error('Screenshot error:', err);
  process.exit(1);
});
