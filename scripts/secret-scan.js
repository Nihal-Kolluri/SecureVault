#!/usr/bin/env node
/**
 * Pre-commit Secret Scanner
 * Ensures no real secrets, private keys, tokens, or untracked .env files are committed.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Patterns for forbidden filenames / extensions
const FORBIDDEN_FILE_PATTERNS = [
  /^\.env(\..+)?$/i, // Matches .env, .env.local, .env.production, etc.
  /\.pem$/i,
  /\.key$/i,
  /\.pfx$/i,
  /\.p12$/i,
  /id_rsa/i,
  /id_ed25519/i,
];

// Whitelisted files
const ALLOWED_FILES = [
  '.env.example',
  '.env.template',
];

// Content regex patterns for detecting leaked secrets
const SECRET_PATTERNS = [
  {
    name: 'Private Key',
    regex: /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----/,
  },
  {
    name: 'AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/,
  },
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}/,
  },
  {
    name: 'Stripe Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24}/,
  },
  {
    name: 'Generic API Key / Secret',
    regex: /(?:secret|api[_-]?key|password|access[_-]?token|private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9+/=_\-\.]{20,})["']/i,
  },
];

function getStagedFiles() {
  try {
    const output = execSync('git diff --cached --name-only --diff-filter=ACM', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    return output
      .split('\n')
      .map((f) => f.trim())
      .filter((f) => f.length > 0);
  } catch (error) {
    return [];
  }
}

function scan() {
  const stagedFiles = getStagedFiles();
  if (stagedFiles.length === 0) {
    process.exit(0);
  }

  let hasErrors = false;

  for (const file of stagedFiles) {
    const baseName = path.basename(file);

    // 1. Check filename patterns
    if (!ALLOWED_FILES.includes(baseName)) {
      for (const pattern of FORBIDDEN_FILE_PATTERNS) {
        if (pattern.test(baseName)) {
          console.error(`\x1b[31m[ERROR]\x1b[0m Forbidden file staged for commit: ${file}`);
          console.error(`        Files matching ${pattern} must never be committed.`);
          hasErrors = true;
        }
      }
    }

    // 2. Check staged content
    if (!fs.existsSync(file)) {
      continue;
    }

    // Skip scanning binary files or large files > 1MB
    const stats = fs.statSync(file);
    if (stats.size > 1024 * 1024) {
      continue;
    }

    let content = '';
    try {
      // Get staged version of the content
      content = execSync(`git show :${file}`, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      });
    } catch {
      try {
        content = fs.readFileSync(file, 'utf8');
      } catch {
        continue;
      }
    }

    // Skip files designed to describe patterns (like this scanner script itself)
    if (file === 'scripts/secret-scan.js') {
      continue;
    }

    for (const { name, regex } of SECRET_PATTERNS) {
      if (regex.test(content)) {
        console.error(`\x1b[31m[ERROR]\x1b[0m Potential secret detected in ${file}: "${name}"`);
        console.error(`        Check the staged diff and remove hardcoded credentials before committing.`);
        hasErrors = true;
      }
    }
  }

  if (hasErrors) {
    console.error('\x1b[31m[FAILED]\x1b[0m Pre-commit secret scan failed. Commit aborted.');
    process.exit(1);
  }

  console.log('\x1b[32m[PASSED]\x1b[0m Pre-commit secret scan completed with no secrets detected.');
}

scan();
