// Global session state
let sessionState = {
  accessToken: null,
  refreshToken: null,
  user: null,
  tokenExpiresAt: null,
  countdownInterval: null,
  mfaPendingToken: null,
  pendingSetupToken: null,
  currentRecoveryCodes: [],
  vaultItems: [],
  files: [],
  currentVaultView: 'secrets',
  currentCategory: 'all',
  searchQuery: '',
  revealedSecrets: {},
  autoMaskTimers: {}
};

// Switch between Sign In and Register tabs
function switchTab(tab) {
  hideAlert();
  const tabSignIn = document.getElementById('tabSignIn');
  const tabRegister = document.getElementById('tabRegister');
  const signInForm = document.getElementById('signInForm');
  const registerForm = document.getElementById('registerForm');
  const vaultDashboard = document.getElementById('vaultDashboard');
  const mfaVerifyView = document.getElementById('mfaVerifyView');
  const mfaSetupView = document.getElementById('mfaSetupView');

  vaultDashboard.classList.add('hidden');
  mfaVerifyView.classList.add('hidden');
  mfaSetupView.classList.add('hidden');

  if (tab === 'signin') {
    tabSignIn.classList.add('active');
    tabSignIn.setAttribute('aria-selected', 'true');
    tabRegister.classList.remove('active');
    tabRegister.setAttribute('aria-selected', 'false');

    signInForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
  } else {
    tabRegister.classList.add('active');
    tabRegister.setAttribute('aria-selected', 'true');
    tabSignIn.classList.remove('active');
    tabSignIn.setAttribute('aria-selected', 'false');

    registerForm.classList.remove('hidden');
    signInForm.classList.add('hidden');
  }
}

// Toggle password visibility
function togglePasswordVisibility(inputId, button) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  button.style.color = isPassword ? 'var(--accent-cyan)' : 'var(--text-dim)';
}

// Check live password requirements on registration input
function checkPasswordRequirements(value) {
  const reqLength = document.getElementById('reqLength');
  const reqUpper = document.getElementById('reqUpper');
  const reqNumber = document.getElementById('reqNumber');
  const reqSpecial = document.getElementById('reqSpecial');

  const hasLength = value.length >= 8;
  const hasUpper = /[A-Z]/.test(value) && /[a-z]/.test(value);
  const hasNumber = /[0-9]/.test(value);
  const hasSpecial = /[^A-Za-z0-9]/.test(value);

  reqLength.classList.toggle('met', hasLength);
  reqUpper.classList.toggle('met', hasUpper);
  reqNumber.classList.toggle('met', hasNumber);
  reqSpecial.classList.toggle('met', hasSpecial);
}

// Show alert banner
function showAlert(message, type = 'error') {
  const alertBox = document.getElementById('alertBox');
  const alertText = document.getElementById('alertText');
  alertText.textContent = message;
  alertBox.className = `alert-box ${type}`;
}

// Hide alert banner
function hideAlert() {
  const alertBox = document.getElementById('alertBox');
  alertBox.className = 'alert-box hidden';
}

// Handle Sign In submission
async function handleSignIn(event) {
  event.preventDefault();
  hideAlert();

  const email = document.getElementById('signinEmail').value.trim();
  const password = document.getElementById('signinPassword').value;
  const submitBtn = document.getElementById('signInBtn');
  const btnText = submitBtn.querySelector('.btn-text');
  const btnSpinner = submitBtn.querySelector('.btn-spinner');

  submitBtn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Invalid email or password.');
    }

    if (data.mfaRequired) {
      // Transition to Six-Box MFA Verification screen
      showMfaVerification(data.mfaToken);
      return;
    }

    // Direct password success (no MFA enabled)
    setSession(data);
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    submitBtn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
  }
}

// Handle Registration submission
async function handleRegister(event) {
  event.preventDefault();
  hideAlert();

  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  const submitBtn = document.getElementById('registerBtn');
  const btnText = submitBtn.querySelector('.btn-text');
  const btnSpinner = submitBtn.querySelector('.btn-spinner');

  submitBtn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Failed to create account.');
    }

    showAlert('Vault account registered successfully! Please sign in.', 'success');
    document.getElementById('registerForm').reset();
    document.getElementById('signinEmail').value = email;
    setTimeout(() => {
      switchTab('signin');
    }, 1200);
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    submitBtn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
  }
}

/* -------------------------------------------------------------------------- */
/*                       Six-Box MFA Verification Logic                       */
/* -------------------------------------------------------------------------- */

function showMfaVerification(mfaToken) {
  sessionState.mfaPendingToken = mfaToken;

  document.getElementById('signInForm').classList.add('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'none';

  const mfaView = document.getElementById('mfaVerifyView');
  mfaView.classList.remove('hidden');

  toggleRecoveryMode(false);
  clearMfaBoxes();

  const boxes = document.querySelectorAll('.mfa-box');
  if (boxes.length > 0) {
    setTimeout(() => boxes[0].focus(), 100);
  }

  showAlert('Two-factor authentication required. Please enter your 6-digit code.', 'success');
}

function clearMfaBoxes() {
  const boxes = document.querySelectorAll('.mfa-box');
  boxes.forEach((box) => (box.value = ''));
}

function getMfaBoxesValue() {
  const boxes = document.querySelectorAll('.mfa-box');
  let code = '';
  boxes.forEach((b) => (code += b.value));
  return code;
}

function initSixBoxes() {
  const boxes = document.querySelectorAll('.mfa-box');

  boxes.forEach((box, idx) => {
    box.addEventListener('input', (e) => {
      const val = e.target.value.replace(/[^0-9]/g, '');
      box.value = val;

      if (val && idx < boxes.length - 1) {
        boxes[idx + 1].focus();
      }

      // If all 6 boxes are filled, auto-submit
      if (getMfaBoxesValue().length === 6) {
        submitMfaCode();
      }
    });

    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && idx > 0) {
        boxes[idx - 1].focus();
      } else if (e.key === 'ArrowLeft' && idx > 0) {
        boxes[idx - 1].focus();
      } else if (e.key === 'ArrowRight' && idx < boxes.length - 1) {
        boxes[idx + 1].focus();
      }
    });

    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData('text');
      const digits = text.replace(/[^0-9]/g, '').slice(0, 6);

      digits.split('').forEach((d, i) => {
        if (boxes[i]) boxes[i].value = d;
      });

      if (digits.length === 6) {
        boxes[5].focus();
        submitMfaCode();
      } else if (digits.length > 0) {
        const nextIdx = Math.min(digits.length, boxes.length - 1);
        boxes[nextIdx].focus();
      }
    });
  });
}

function toggleRecoveryMode(showRecovery) {
  hideAlert();
  const totpSection = document.getElementById('totpInputSection');
  const recoverySection = document.getElementById('recoveryInputSection');
  const promptText = document.getElementById('mfaPromptText');

  if (showRecovery) {
    totpSection.classList.add('hidden');
    recoverySection.classList.remove('hidden');
    promptText.textContent = 'Enter an 8-character emergency recovery code (XXXX-XXXX).';
    const recInput = document.getElementById('recoveryCodeInput');
    recInput.value = '';
    setTimeout(() => recInput.focus(), 50);
  } else {
    totpSection.classList.remove('hidden');
    recoverySection.classList.add('hidden');
    promptText.textContent = 'Enter the 6-digit verification code from your authenticator app.';
    clearMfaBoxes();
    const boxes = document.querySelectorAll('.mfa-box');
    if (boxes[0]) setTimeout(() => boxes[0].focus(), 50);
  }
}

async function submitMfaCode() {
  hideAlert();
  const code = getMfaBoxesValue();

  if (code.length !== 6) {
    showAlert('Please enter all 6 digits of your authenticator code.', 'error');
    return;
  }

  const btn = document.getElementById('mfaVerifyBtn');
  const btnText = btn.querySelector('.btn-text');
  const btnSpinner = btn.querySelector('.btn-spinner');

  btn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');

  try {
    const res = await fetch('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mfaToken: sessionState.mfaPendingToken,
        code
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Invalid authentication code.');
    }

    document.getElementById('mfaVerifyView').classList.add('hidden');
    setSession(data);
  } catch (err) {
    showAlert(err.message, 'error');
    clearMfaBoxes();
    const boxes = document.querySelectorAll('.mfa-box');
    if (boxes[0]) boxes[0].focus();
  } finally {
    btn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
  }
}

async function submitRecoveryCode() {
  hideAlert();
  const rawCode = document.getElementById('recoveryCodeInput').value.trim();

  if (!rawCode) {
    showAlert('Please enter your recovery code.', 'error');
    return;
  }

  const btn = document.getElementById('recoveryVerifyBtn');
  const btnText = btn.querySelector('.btn-text');
  const btnSpinner = btn.querySelector('.btn-spinner');

  btn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');

  try {
    const res = await fetch('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mfaToken: sessionState.mfaPendingToken,
        recoveryCode: rawCode
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Invalid recovery code.');
    }

    document.getElementById('mfaVerifyView').classList.add('hidden');
    setSession(data);
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    btn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
  }
}

function cancelMfaVerification() {
  sessionState.mfaPendingToken = null;
  document.getElementById('mfaVerifyView').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'flex';
  switchTab('signin');
}

/* -------------------------------------------------------------------------- */
/*                        Dashboard & MFA Enrollment                          */
/* -------------------------------------------------------------------------- */

function setSession(data) {
  sessionState.accessToken = data.accessToken;
  sessionState.refreshToken = data.refreshToken;
  sessionState.user = data.user;
  sessionState.tokenExpiresAt = Date.now() + 15 * 60 * 1000;

  document.getElementById('signInForm').classList.add('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'none';
  document.getElementById('mfaVerifyView').classList.add('hidden');
  document.getElementById('mfaSetupView').classList.add('hidden');

  const wrapper = document.querySelector('.auth-wrapper');
  if (wrapper) wrapper.classList.add('vault-active');

  const dashboard = document.getElementById('vaultDashboard');
  dashboard.classList.remove('hidden');
  document.getElementById('dashUserEmail').textContent = data.user.email;

  updateMfaStatusUI(data.user.mfaEnabled);
  startJwtCountdown();
  fetchMfaStatus();
  fetchVaultItems();
  loadFiles();
  showAlert('Authenticated securely with 15-minute sliding session.', 'success');
}

function updateMfaStatusUI(enabled, remainingCodes = null) {
  const badge = document.getElementById('mfaBadge');
  const subText = document.getElementById('mfaSubText');
  const setupBtn = document.getElementById('mfaSetupBtn');
  const disableBtn = document.getElementById('mfaDisableBtn');

  if (enabled) {
    badge.textContent = 'ACTIVE';
    badge.style.color = '#34d399';
    subText.textContent = remainingCodes !== null ? `${remainingCodes} recovery codes` : 'TOTP protected';
    setupBtn.classList.add('hidden');
    disableBtn.classList.remove('hidden');
  } else {
    badge.textContent = 'DISABLED';
    badge.style.color = 'var(--text-dim)';
    subText.textContent = 'TOTP enrollment available';
    setupBtn.classList.remove('hidden');
    disableBtn.classList.add('hidden');
  }
}

async function fetchMfaStatus() {
  try {
    const res = await fetch('/api/auth/mfa/status', {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      updateMfaStatusUI(data.mfaEnabled, data.remainingRecoveryCodes);
    }
  } catch {
    // Ignore status check error
  }
}

async function openMfaSetup() {
  hideAlert();
  try {
    const res = await fetch('/api/auth/mfa/setup', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${sessionState.accessToken}`
      }
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start MFA setup');

    sessionState.pendingSetupToken = data.setupToken;
    sessionState.currentRecoveryCodes = data.recoveryCodes;

    document.getElementById('vaultDashboard').classList.add('hidden');
    const setupView = document.getElementById('mfaSetupView');
    setupView.classList.remove('hidden');

    document.getElementById('mfaQrImage').src = data.qrCode;
    document.getElementById('mfaSecretCode').textContent = data.secret;

    const grid = document.getElementById('recoveryCodesGrid');
    grid.innerHTML = '';
    data.recoveryCodes.forEach((code) => {
      const tag = document.createElement('div');
      tag.className = 'recovery-code-tag';
      tag.textContent = code;
      grid.appendChild(tag);
    });

    document.getElementById('mfaConfirmCode').value = '';
    setTimeout(() => document.getElementById('mfaConfirmCode').focus(), 100);
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

function closeMfaSetup() {
  sessionState.pendingSetupToken = null;
  document.getElementById('mfaSetupView').classList.add('hidden');
  document.getElementById('vaultDashboard').classList.remove('hidden');
}

function copyRecoveryCodes() {
  if (!sessionState.currentRecoveryCodes.length) return;
  const text = sessionState.currentRecoveryCodes.join('\n');
  navigator.clipboard.writeText(text).then(() => {
    showAlert('Recovery codes copied to clipboard! Store them safely.', 'success');
  }).catch(() => {
    showAlert('Failed to copy. Please manually copy the codes.', 'error');
  });
}

async function submitMfaConfirmation() {
  hideAlert();
  const code = document.getElementById('mfaConfirmCode').value.trim();

  if (!code || code.length !== 6) {
    showAlert('Please enter the 6-digit confirmation code from your app.', 'error');
    return;
  }

  const btn = document.getElementById('confirmMfaBtn');
  const btnText = btn.querySelector('.btn-text');
  const btnSpinner = btn.querySelector('.btn-spinner');

  btn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');

  try {
    const res = await fetch('/api/auth/mfa/confirm', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionState.accessToken}`
      },
      body: JSON.stringify({
        setupToken: sessionState.pendingSetupToken,
        code
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to confirm MFA');

    closeMfaSetup();
    updateMfaStatusUI(true, 8);
    showAlert('Two-factor authentication successfully enabled!', 'success');
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    btn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
  }
}

async function handleDisableMfa() {
  if (!confirm('Are you sure you want to disable two-factor authentication?')) return;
  hideAlert();

  try {
    const res = await fetch('/api/auth/mfa/disable', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${sessionState.accessToken}`
      }
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to disable MFA');

    updateMfaStatusUI(false);
    showAlert('Two-factor authentication disabled.', 'success');
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

function startJwtCountdown() {
  if (sessionState.countdownInterval) {
    clearInterval(sessionState.countdownInterval);
  }

  const countdownElem = document.getElementById('jwtCountdown');

  function update() {
    const remainingMs = sessionState.tokenExpiresAt - Date.now();
    if (remainingMs <= 0) {
      countdownElem.textContent = 'EXPIRED';
      countdownElem.style.color = 'var(--danger-color)';
      clearInterval(sessionState.countdownInterval);
      return;
    }

    const totalSeconds = Math.floor(remainingMs / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    countdownElem.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  }

  update();
  sessionState.countdownInterval = setInterval(update, 1000);
}

async function testProtectedEndpoint() {
  const outputBox = document.getElementById('apiOutput');
  const codeElem = document.getElementById('apiOutputCode');
  outputBox.classList.remove('hidden');
  codeElem.textContent = 'Calling GET /api/auth/me...';

  try {
    const res = await fetch('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${sessionState.accessToken}`
      }
    });
    const json = await res.json();
    codeElem.textContent = JSON.stringify(json, null, 2);
  } catch (err) {
    codeElem.textContent = `Error: ${err.message}`;
  }
}

async function triggerTokenRefresh() {
  hideAlert();
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: sessionState.refreshToken })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Refresh failed');

    sessionState.accessToken = data.accessToken;
    sessionState.refreshToken = data.refreshToken;
    sessionState.tokenExpiresAt = Date.now() + 15 * 60 * 1000;
    startJwtCountdown();

    showAlert('Session token rotated successfully. Previous token invalidated.', 'success');
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleLogout() {
  if (sessionState.countdownInterval) {
    clearInterval(sessionState.countdownInterval);
  }

  // Clear all auto-mask timers
  Object.values(sessionState.autoMaskTimers).forEach((timer) => clearInterval(timer));
  sessionState.autoMaskTimers = {};
  sessionState.revealedSecrets = {};

  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: sessionState.refreshToken })
    });
  } catch {
    // Ignore network error
  }

  sessionState = {
    accessToken: null,
    refreshToken: null,
    user: null,
    tokenExpiresAt: null,
    countdownInterval: null,
    mfaPendingToken: null,
    pendingSetupToken: null,
    currentRecoveryCodes: [],
    vaultItems: [],
    currentCategory: 'all',
    searchQuery: '',
    revealedSecrets: {},
    autoMaskTimers: {}
  };

  const wrapper = document.querySelector('.auth-wrapper');
  if (wrapper) wrapper.classList.remove('vault-active');

  document.getElementById('vaultDashboard').classList.add('hidden');
  document.getElementById('mfaVerifyView').classList.add('hidden');
  document.getElementById('mfaSetupView').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'flex';
  document.getElementById('apiOutput').classList.add('hidden');
  switchTab('signin');
  showAlert('Vault session terminated securely.', 'success');
}

/* -------------------------------------------------------------------------- */
/*                        Vault Items & Secrets Screen                        */
/* -------------------------------------------------------------------------- */

async function fetchVaultItems() {
  const container = document.getElementById('vaultItemsList');
  if (!sessionState.accessToken) return;

  try {
    const res = await fetch('/api/vault/items', {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });

    if (res.ok) {
      const data = await res.json();
      sessionState.vaultItems = data.items || [];
      const countEl = document.getElementById('vaultItemCount');
      if (countEl) countEl.textContent = sessionState.vaultItems.length;

      // Update KEK metric if available
      if (sessionState.vaultItems.length > 0) {
        const kekEl = document.getElementById('kekMetric');
        if (kekEl) kekEl.textContent = sessionState.vaultItems[0].kek_version.toUpperCase();
      }

      renderVaultItems();
    } else {
      container.innerHTML = '<div class="vault-empty-state">Failed to load vault items.</div>';
    }
  } catch {
    container.innerHTML = '<div class="vault-empty-state">Network error connecting to vault API.</div>';
  }
}

function setCategoryFilter(category) {
  sessionState.currentCategory = category;
  document.querySelectorAll('.cat-pill').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.cat === category);
  });
  renderVaultItems();
}

function filterVaultItems() {
  const input = document.getElementById('vaultSearchInput');
  sessionState.searchQuery = input ? input.value.trim().toLowerCase() : '';
  renderVaultItems();
}

function renderVaultItems() {
  const container = document.getElementById('vaultItemsList');
  if (!container) return;

  let items = sessionState.vaultItems;

  // Filter by category
  if (sessionState.currentCategory !== 'all') {
    items = items.filter((item) => (item.category || 'secret') === sessionState.currentCategory);
  }

  // Filter by search query
  if (sessionState.searchQuery) {
    items = items.filter((item) => item.title.toLowerCase().includes(sessionState.searchQuery));
  }

  if (items.length === 0) {
    container.innerHTML = `
      <div class="vault-empty-state">
        <svg style="width:36px;height:36px;color:var(--text-dim);" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        <span>No encrypted secrets stored yet.</span>
        <button type="button" class="action-btn secondary" style="padding:6px 14px;font-size:12px;" onclick="openCreateItemModal()">+ Store First Secret</button>
      </div>
    `;
    return;
  }

  const categoryIcons = {
    api_key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>',
    password: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
    note: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>',
    certificate: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;"><circle cx="12" cy="8" r="7"></circle><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"></polyline></svg>'
  };

  container.innerHTML = items.map((item) => {
    const isRevealed = Boolean(sessionState.revealedSecrets[item.id]);
    const revealedVal = sessionState.revealedSecrets[item.id] || '';
    const displayValue = isRevealed ? escapeHtml(revealedVal) : '••••••••••••••••••••••••';
    const isOwner = item.access_level === 'owner';
    const accessBadge = isOwner 
      ? '<span class="badge-owner">OWNER</span>' 
      : `<span class="badge-shared">${item.access_level ? item.access_level.toUpperCase() : 'SHARED'}</span>`;

    const icon = categoryIcons[item.category] || categoryIcons.password;

    return `
      <article class="vault-item-card" id="card-${item.id}">
        <div class="item-card-header">
          <div class="item-title-group">
            <div class="item-icon-tag">${icon}</div>
            <span class="item-title">${escapeHtml(item.title)}</span>
          </div>
          <div class="item-badges">
            ${accessBadge}
            <span class="badge-version">v${item.current_version || 1}</span>
          </div>
        </div>

        <!-- Masked Secret Box -->
        <div class="masked-secret-box">
          <div class="masked-value ${isRevealed ? 'revealed' : ''}" id="secret-val-${item.id}">${displayValue}</div>
          <div class="secret-controls">
            ${isRevealed ? `<span class="auto-hide-pill" id="autohide-${item.id}">Auto-mask 30s</span>` : ''}
            <button 
              type="button" 
              class="icon-btn ${isRevealed ? 'revealed' : ''}" 
              id="reveal-btn-${item.id}"
              onclick="toggleRevealSecret('${item.id}')"
              title="${isRevealed ? 'Hide secret' : 'Reveal secret'}"
            >
              ${isRevealed ? '🔒 Mask' : '👁️ Reveal'}
            </button>
            <button 
              type="button" 
              class="icon-btn copy-btn" 
              id="copy-btn-${item.id}"
              onclick="copySecretToClipboard('${item.id}', this)"
              title="Copy secret to clipboard"
            >
              📋 Copy
            </button>
          </div>
        </div>

        <div class="item-card-footer">
          <span class="card-meta">Updated ${new Date(item.updated_at || item.created_at).toLocaleDateString()} • KEK: ${item.kek_version}</span>
          <div class="card-actions">
            <button type="button" class="icon-btn" onclick="openVersionsModal('${item.id}', '${escapeJs(item.title)}')">
              🕒 History
            </button>
            ${isOwner ? `
              <button type="button" class="icon-btn" onclick="openShareModal('${item.id}', '${escapeJs(item.title)}')">
                👥 Share
              </button>
            ` : ''}
            ${(isOwner || item.access_level === 'write') ? `
              <button type="button" class="icon-btn" onclick="openEditItemModal('${item.id}')">
                ✏️ Edit
              </button>
            ` : ''}
            ${isOwner ? `
              <button type="button" class="icon-btn" style="color:#f87171;" onclick="handleDeleteItem('${item.id}')">
                🗑️
              </button>
            ` : ''}
          </div>
        </div>
      </article>
    `;
  }).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeJs(str) {
  if (!str) return '';
  return String(str).replace(/'/g, "\\'").replace(/"/g, '\\"');
}

/* -------------------------------------------------------------------------- */
/*                       Masked / Reveal / Copy Behavior                      */
/* -------------------------------------------------------------------------- */

async function toggleRevealSecret(itemId) {
  const valEl = document.getElementById(`secret-val-${itemId}`);
  const btnEl = document.getElementById(`reveal-btn-${itemId}`);
  if (!valEl || !btnEl) return;

  // If already revealed -> mask it
  if (sessionState.revealedSecrets[itemId]) {
    delete sessionState.revealedSecrets[itemId];
    if (sessionState.autoMaskTimers[itemId]) {
      clearInterval(sessionState.autoMaskTimers[itemId]);
      delete sessionState.autoMaskTimers[itemId];
    }
    renderVaultItems();
    return;
  }

  // Fetch and decrypt
  try {
    btnEl.textContent = '...';
    const res = await fetch(`/api/vault/items/${itemId}`, {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });

    if (!res.ok) {
      throw new Error('Failed to decrypt secret');
    }

    const data = await res.json();
    sessionState.revealedSecrets[itemId] = data.secret;

    // Start 30s auto-mask timer
    let remaining = 30;
    if (sessionState.autoMaskTimers[itemId]) {
      clearInterval(sessionState.autoMaskTimers[itemId]);
    }

    sessionState.autoMaskTimers[itemId] = setInterval(() => {
      remaining--;
      const pill = document.getElementById(`autohide-${itemId}`);
      if (pill) pill.textContent = `Auto-mask ${remaining}s`;

      if (remaining <= 0) {
        clearInterval(sessionState.autoMaskTimers[itemId]);
        delete sessionState.autoMaskTimers[itemId];
        delete sessionState.revealedSecrets[itemId];
        renderVaultItems();
      }
    }, 1000);

    renderVaultItems();
  } catch (err) {
    showAlert(err.message, 'error');
    renderVaultItems();
  }
}

async function copySecretToClipboard(itemId, btn) {
  let secret = sessionState.revealedSecrets[itemId];

  if (!secret) {
    try {
      const res = await fetch(`/api/vault/items/${itemId}`, {
        headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        secret = data.secret;
      }
    } catch {
      // Ignore
    }
  }

  if (!secret) {
    showAlert('Unable to decrypt secret for copying.', 'error');
    return;
  }

  // Copy to clipboard
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(secret);
    } else {
      const ta = document.createElement('textarea');
      ta.value = secret;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }

    const origText = btn.innerHTML;
    btn.innerHTML = '✓ Copied!';
    btn.style.color = '#34d399';
    btn.style.borderColor = 'rgba(16, 185, 129, 0.4)';

    setTimeout(() => {
      btn.innerHTML = origText;
      btn.style.color = '';
      btn.style.borderColor = '';
    }, 2000);
  } catch {
    showAlert('Clipboard write permission denied.', 'error');
  }
}

/* -------------------------------------------------------------------------- */
/*                       Create / Edit Item Modal Handlers                    */
/* -------------------------------------------------------------------------- */

function openCreateItemModal() {
  document.getElementById('editItemId').value = '';
  document.getElementById('itemModalTitle').textContent = 'Store Encrypted Secret';
  document.getElementById('itemTitleInput').value = '';
  document.getElementById('itemCategorySelect').value = 'api_key';
  document.getElementById('itemSecretInput').value = '';
  document.getElementById('vaultItemModal').classList.remove('hidden');
}

function openEditItemModal(itemId) {
  const item = sessionState.vaultItems.find((i) => i.id === itemId);
  if (!item) return;

  document.getElementById('editItemId').value = item.id;
  document.getElementById('itemModalTitle').textContent = `Update Secret: ${item.title} (New Version)`;
  document.getElementById('itemTitleInput').value = item.title;
  document.getElementById('itemCategorySelect').value = item.category || 'api_key';
  document.getElementById('itemSecretInput').value = sessionState.revealedSecrets[itemId] || '';
  document.getElementById('vaultItemModal').classList.remove('hidden');
}

function closeItemModal() {
  document.getElementById('vaultItemModal').classList.add('hidden');
}

function generateRandomSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}';
  let result = '';
  const cryptoObj = window.crypto || window.msCrypto;
  const values = new Uint32Array(24);
  cryptoObj.getRandomValues(values);
  for (let i = 0; i < 24; i++) {
    result += chars[values[i] % chars.length];
  }
  document.getElementById('itemSecretInput').value = result;
}

async function handleSaveVaultItem(event) {
  event.preventDefault();
  const itemId = document.getElementById('editItemId').value;
  const title = document.getElementById('itemTitleInput').value.trim();
  const category = document.getElementById('itemCategorySelect').value;
  const secret = document.getElementById('itemSecretInput').value;

  const btn = document.getElementById('saveItemBtn');
  btn.disabled = true;

  try {
    const isEdit = Boolean(itemId);
    const url = isEdit ? `/api/vault/items/${itemId}` : '/api/vault/items';
    const method = isEdit ? 'PUT' : 'POST';

    const res = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionState.accessToken}`
      },
      body: JSON.stringify({ title, category, secret })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Failed to save vault item.');
    }

    closeItemModal();
    showAlert(isEdit ? 'Vault item updated! Created new version.' : 'Encrypted secret stored successfully.', 'success');
    await fetchVaultItems();
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function handleDeleteItem(itemId) {
  if (!confirm('Are you sure you want to permanently delete this secret and all its version history?')) {
    return;
  }

  try {
    const res = await fetch(`/api/vault/items/${itemId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });

    if (res.ok) {
      showAlert('Vault item permanently deleted.', 'success');
      await fetchVaultItems();
    } else {
      const data = await res.json();
      throw new Error(data.error || 'Failed to delete vault item.');
    }
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

/* -------------------------------------------------------------------------- */
/*                         Version History Modal Handlers                     */
/* -------------------------------------------------------------------------- */

async function openVersionsModal(itemId, title) {
  document.getElementById('versionModalItemTitle').textContent = title;
  const container = document.getElementById('versionsListContainer');
  container.innerHTML = '<span class="btn-spinner"></span> Loading version history...';
  document.getElementById('vaultVersionsModal').classList.remove('hidden');

  try {
    const res = await fetch(`/api/vault/items/${itemId}/versions`, {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });

    if (!res.ok) throw new Error('Failed to load version history.');
    const data = await res.json();
    const versions = data.versions || [];

    container.innerHTML = versions.map((v) => `
      <div class="version-row">
        <div class="version-info">
          <span class="version-title">Version ${v.version}</span>
          <span class="version-meta">Created ${new Date(v.created_at).toLocaleString()} • KEK: ${v.kek_version} (${v.algorithm})</span>
          <div id="v-secret-${v.version}" style="font-family:var(--font-mono);font-size:11.5px;color:#38bdf8;margin-top:4px;"></div>
        </div>
        <button 
          type="button" 
          class="icon-btn" 
          onclick="decryptSpecificVersion('${itemId}', ${v.version}, 'v-secret-${v.version}')"
        >
          🔍 View & Decrypt
        </button>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<span style="color:#f87171;">${err.message}</span>`;
  }
}

async function decryptSpecificVersion(itemId, version, targetElId) {
  const el = document.getElementById(targetElId);
  if (!el) return;
  el.textContent = 'Decrypting...';

  try {
    const res = await fetch(`/api/vault/items/${itemId}?version=${version}`, {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });
    if (!res.ok) throw new Error('Decryption failed');
    const data = await res.json();
    el.textContent = `Payload: ${data.secret}`;
  } catch (err) {
    el.textContent = `Error: ${err.message}`;
  }
}

function closeVersionsModal() {
  document.getElementById('vaultVersionsModal').classList.add('hidden');
}

/* -------------------------------------------------------------------------- */
/*                            Sharing Modal Handlers                          */
/* -------------------------------------------------------------------------- */

async function openShareModal(itemId, title) {
  document.getElementById('shareModalItemTitle').textContent = title;
  document.getElementById('shareItemId').value = itemId;
  document.getElementById('shareUserEmail').value = '';
  document.getElementById('vaultShareModal').classList.remove('hidden');
  await loadSharesList(itemId);
}

async function loadSharesList(itemId) {
  const container = document.getElementById('sharesListContainer');
  container.innerHTML = '<span>Loading collaborators...</span>';

  try {
    const res = await fetch(`/api/vault/items/${itemId}/shares`, {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });
    if (!res.ok) throw new Error('Failed to load shares.');
    const data = await res.json();
    const shares = data.shares || [];

    if (shares.length === 0) {
      container.innerHTML = '<span style="color:var(--text-dim);font-size:12px;">No collaborators have been granted access yet.</span>';
      return;
    }

    container.innerHTML = shares.map((s) => `
      <div class="share-row">
        <div class="share-info">
          <span class="share-email">${escapeHtml(s.shared_with_email)}</span>
          <span class="share-permission">Permission: ${s.permission.toUpperCase()}</span>
        </div>
        <button 
          type="button" 
          class="icon-btn" 
          style="color:#f87171;" 
          onclick="handleRevokeShare('${itemId}', '${s.shared_with_user_id}')"
        >
          Revoke
        </button>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<span style="color:#f87171;">${err.message}</span>`;
  }
}

async function handleAddShare(event) {
  event.preventDefault();
  const itemId = document.getElementById('shareItemId').value;
  const email = document.getElementById('shareUserEmail').value.trim();
  const permission = document.getElementById('sharePermissionSelect').value;

  try {
    const res = await fetch(`/api/vault/items/${itemId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionState.accessToken}`
      },
      body: JSON.stringify({ email, permission })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to grant share permission.');

    document.getElementById('shareUserEmail').value = '';
    showAlert(`Access granted to ${email}.`, 'success');
    await loadSharesList(itemId);
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function handleRevokeShare(itemId, userId) {
  try {
    const res = await fetch(`/api/vault/items/${itemId}/share/${userId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });

    if (res.ok) {
      showAlert('Collaborator access revoked.', 'success');
      await loadSharesList(itemId);
    } else {
      const data = await res.json();
      throw new Error(data.error || 'Failed to revoke access.');
    }
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

function closeShareModal() {
  document.getElementById('vaultShareModal').classList.add('hidden');
}

/* -------------------------------------------------------------------------- */
/*                           Key Rotation Handler                             */
/* -------------------------------------------------------------------------- */

async function handleRotateMasterKey() {
  if (!confirm('Rotate active Key Encryption Key (KEK)? All stored DEKs will be securely re-wrapped under a new key version.')) {
    return;
  }

  try {
    const newVersion = `kek_v${Date.now()}`;
    const res = await fetch('/api/vault/rotate-keys', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionState.accessToken}`
      },
      body: JSON.stringify({ newVersion })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Key rotation failed.');

    const kekEl = document.getElementById('kekMetric');
    if (kekEl) kekEl.textContent = data.activeKekVersion.toUpperCase();

    showAlert(`Key rotation successful! Re-wrapped ${data.itemsRotated} item DEKs and ${data.versionsRotated} version DEKs.`, 'success');
    await fetchVaultItems();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

/* -------------------------------------------------------------------------- */
/*                 Phase 5: Encrypted Files & MinIO Handlers                  */
/* -------------------------------------------------------------------------- */

function switchVaultView(view) {
  sessionState.currentVaultView = view;
  const tabSecrets = document.getElementById('viewTabSecrets');
  const tabFiles = document.getElementById('viewTabFiles');
  const secSecrets = document.getElementById('secretsViewSection');
  const secFiles = document.getElementById('filesViewSection');
  const btnStoreSecret = document.getElementById('storeNewSecretBtn');
  const btnUploadFile = document.getElementById('uploadFileActionBtn');

  if (view === 'secrets') {
    if (tabSecrets) tabSecrets.classList.add('active');
    if (tabFiles) tabFiles.classList.remove('active');
    if (secSecrets) secSecrets.classList.remove('hidden');
    if (secFiles) secFiles.classList.add('hidden');
    if (btnStoreSecret) btnStoreSecret.classList.remove('hidden');
    if (btnUploadFile) btnUploadFile.classList.add('hidden');
  } else {
    if (tabFiles) tabFiles.classList.add('active');
    if (tabSecrets) tabSecrets.classList.remove('active');
    if (secFiles) secFiles.classList.remove('hidden');
    if (secSecrets) secSecrets.classList.add('hidden');
    if (btnUploadFile) btnUploadFile.classList.remove('hidden');
    if (btnStoreSecret) btnStoreSecret.classList.add('hidden');
    loadFiles();
  }
}

function triggerFileInput() {
  const input = document.getElementById('fileUploadInput');
  if (input) input.click();
}

function handleDragOver(e) {
  e.preventDefault();
  e.stopPropagation();
  const dropZone = document.getElementById('fileDropZone');
  if (dropZone) dropZone.classList.add('drag-active');
}

function handleDragLeave(e) {
  e.preventDefault();
  e.stopPropagation();
  const dropZone = document.getElementById('fileDropZone');
  if (dropZone) dropZone.classList.remove('drag-active');
}

function handleFileDrop(e) {
  e.preventDefault();
  e.stopPropagation();
  const dropZone = document.getElementById('fileDropZone');
  if (dropZone) dropZone.classList.remove('drag-active');

  const files = e.dataTransfer && e.dataTransfer.files;
  if (files && files.length > 0) {
    uploadEncryptedFile(files[0]);
  }
}

function handleFileSelected(e) {
  const file = e.target.files && e.target.files[0];
  if (file) {
    uploadEncryptedFile(file);
    e.target.value = '';
  }
}

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function uploadEncryptedFile(file) {
  hideAlert();
  const MAX_LIMIT = 50 * 1024 * 1024; // 50MB
  if (file.size > MAX_LIMIT) {
    showAlert(`File exceeds maximum size limit of ${formatBytes(MAX_LIMIT)}.`, 'error');
    return;
  }

  const card = document.getElementById('uploadProgressCard');
  const nameEl = document.getElementById('progressFileName');
  const sizeEl = document.getElementById('progressFileSize');
  const fillEl = document.getElementById('progressBarFill');
  const statusEl = document.getElementById('progressStatusText');
  const percentEl = document.getElementById('progressPercentText');

  card.classList.remove('hidden');
  nameEl.textContent = file.name;
  sizeEl.textContent = formatBytes(file.size);
  fillEl.style.width = '10%';
  statusEl.textContent = 'Encrypting... 10% (Streaming AES-256-GCM)';
  percentEl.textContent = '10%';

  const formData = new FormData();
  formData.append('file', file);

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/files/upload', true);
  if (sessionState.accessToken) {
    xhr.setRequestHeader('Authorization', `Bearer ${sessionState.accessToken}`);
  }

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const pct = Math.min(Math.round((e.loaded / e.total) * 90), 90);
      fillEl.style.width = `${pct}%`;
      percentEl.textContent = `${pct}%`;
      statusEl.textContent = `Encrypting... ${pct}% (Streaming AES-256-GCM to MinIO)`;
    }
  };

  xhr.onload = () => {
    if (xhr.status === 201) {
      fillEl.style.width = '100%';
      percentEl.textContent = '100%';
      statusEl.textContent = 'SHA-256 Checksum Verified • Stored in MinIO';

      try {
        const resp = JSON.parse(xhr.responseText);
        showAlert(`File "${resp.file.filename}" stream-encrypted and stored securely in MinIO!`, 'success');
      } catch {
        showAlert('File encrypted and uploaded successfully.', 'success');
      }

      loadFiles();

      setTimeout(() => {
        card.classList.add('hidden');
      }, 2500);
    } else {
      card.classList.add('hidden');
      try {
        const err = JSON.parse(xhr.responseText);
        showAlert(err.error || 'Upload failed.', 'error');
      } catch {
        showAlert('Upload failed.', 'error');
      }
    }
  };

  xhr.onerror = () => {
    card.classList.add('hidden');
    showAlert('Network error while streaming file to MinIO.', 'error');
  };

  xhr.send(formData);
}

async function loadFiles() {
  const container = document.getElementById('filesItemsList');
  if (!sessionState.accessToken) return;

  if (sessionState.accessToken === 'preview_token') {
    renderFilesList();
    return;
  }

  try {
    const res = await fetch('/api/files', {
      headers: { 'Authorization': `Bearer ${sessionState.accessToken}` }
    });

    if (res.ok) {
      const data = await res.json();
      sessionState.files = data.files || [];
      const fileCountEl = document.getElementById('vaultFileCount');
      if (fileCountEl) fileCountEl.textContent = sessionState.files.length;
      renderFilesList();
    } else {
      container.innerHTML = '<div class="empty-files-placeholder">Failed to load encrypted files from storage.</div>';
    }
  } catch {
    container.innerHTML = '<div class="empty-files-placeholder">Network error communicating with MinIO storage service.</div>';
  }
}

function renderFilesList() {
  const container = document.getElementById('filesItemsList');
  if (!container) return;

  if (sessionState.files.length === 0) {
    container.innerHTML = `
      <div class="empty-files-placeholder">
        <p>No encrypted files stored in MinIO yet.</p>
        <span style="font-size:12px;color:var(--text-dim);">Drag & drop any document, key, archive, or database backup above to encrypt.</span>
      </div>
    `;
    return;
  }

  container.innerHTML = sessionState.files.map((file) => {
    return `
      <article class="file-card" id="file-card-${file.id}">
        <div class="file-card-top">
          <div class="file-info-group">
            <div class="file-icon-badge">
              <svg class="file-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
              </svg>
            </div>
            <div class="file-title-meta">
              <span class="file-card-name">${escapeHtml(file.filename)}</span>
              <span class="file-card-sub">
                <span>${formatBytes(file.sizeBytes)}</span>
                <span>•</span>
                <span>${file.mimeType || 'binary'}</span>
                <span>•</span>
                <span>Ciphertext at rest in MinIO</span>
              </span>
            </div>
          </div>
          <div class="file-card-actions">
            <button 
              type="button" 
              class="action-btn primary small-btn" 
              onclick="handleDownloadFile('${file.id}', '${escapeJs(file.filename)}', this)"
            >
              📥 Decrypt & Download
            </button>
            <button 
              type="button" 
              class="action-btn secondary small-btn" 
              id="verify-btn-${file.id}"
              onclick="handleVerifyFile('${file.id}', this)"
            >
              🛡️ Verify Integrity
            </button>
            <button 
              type="button" 
              class="icon-btn" 
              style="color:#f87171;" 
              onclick="handleDeleteFile('${file.id}')"
              title="Delete from MinIO"
            >
              🗑️
            </button>
          </div>
        </div>
        <div class="file-meta-row">
          <span class="checksum-badge" title="Cryptographic SHA-256 checksum">
            SHA-256: <code>${file.sha256Checksum ? file.sha256Checksum.slice(0, 16) + '...' + file.sha256Checksum.slice(-8) : 'N/A'}</code>
            <button type="button" class="copy-hash-btn" onclick="copyHashToClipboard('${file.sha256Checksum}', this)" title="Copy full SHA-256">
              📋
            </button>
          </span>
          <span class="drop-badge">Encrypted: ${formatBytes(file.encryptedSizeBytes)}</span>
          <span class="drop-badge">${file.kekVersion ? file.kekVersion.toUpperCase() : 'KEK v1'} (${file.algorithm || 'aes-256-gcm'})</span>
          <span style="margin-left:auto;color:var(--text-dim);font-size:11px;">
            Uploaded ${new Date(file.createdAt).toLocaleString()}
          </span>
        </div>
      </article>
    `;
  }).join('');
}

async function handleDownloadFile(fileId, filename, btnEl) {
  hideAlert();
  let originalHtml = '';
  if (btnEl) {
    originalHtml = btnEl.innerHTML;
    btnEl.innerHTML = '<span class="btn-spinner"></span> Decrypting...';
    btnEl.disabled = true;
  }

  try {
    const res = await fetch(`/api/files/${fileId}/download`, {
      headers: {
        'Authorization': `Bearer ${sessionState.accessToken}`
      }
    });

    if (!res.ok) {
      let errMsg = 'Failed to download file';
      try {
        const errJson = await res.json();
        errMsg = errJson.error || errMsg;
      } catch {}
      throw new Error(errMsg);
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);

    showAlert(`File "${filename}" stream-decrypted and downloaded successfully.`, 'success');
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    if (btnEl) {
      btnEl.innerHTML = originalHtml;
      btnEl.disabled = false;
    }
  }
}

async function handleVerifyFile(fileId, btnEl) {
  hideAlert();
  let originalHtml = '';
  if (btnEl) {
    originalHtml = btnEl.innerHTML;
    btnEl.innerHTML = '<span class="btn-spinner"></span> Checking...';
    btnEl.disabled = true;
  }

  try {
    const res = await fetch(`/api/files/${fileId}/verify`, {
      headers: {
        'Authorization': `Bearer ${sessionState.accessToken}`
      }
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Integrity verification failed');
    }

    if (btnEl) {
      btnEl.outerHTML = '<span class="verify-badge intact">✓ Intact & Authenticated</span>';
    }
    showAlert(`Integrity Verified: File "${data.filename}" is authentic (AES-GCM Auth Tag & SHA-256 match).`, 'success');
  } catch (err) {
    if (btnEl) {
      btnEl.innerHTML = originalHtml;
      btnEl.disabled = false;
    }
    showAlert(`Tamper Alert: ${err.message}`, 'error');
  }
}

async function handleDeleteFile(fileId) {
  if (!confirm('Are you sure you want to permanently delete this encrypted file from MinIO object storage?')) {
    return;
  }
  hideAlert();

  try {
    const res = await fetch(`/api/files/${fileId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${sessionState.accessToken}`
      }
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Delete failed');
    }

    showAlert('Encrypted file deleted from MinIO storage.', 'success');
    await loadFiles();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

function copyHashToClipboard(hash, btnEl) {
  if (!hash) return;
  navigator.clipboard.writeText(hash).then(() => {
    if (btnEl) {
      const oldTitle = btnEl.getAttribute('title');
      btnEl.textContent = '✓';
      btnEl.style.color = '#38ef7d';
      setTimeout(() => {
        btnEl.textContent = '📋';
        btnEl.style.color = '';
        btnEl.setAttribute('title', oldTitle);
      }, 1500);
    }
  });
}

// Initialize on DOM load
window.addEventListener('DOMContentLoaded', () => {
  initSixBoxes();

  // Query parameter handling for UI previews and documentation screenshots
  const params = new URLSearchParams(window.location.search);
  const view = params.get('view');

  if (view === 'mfa-verify') {
    showMfaVerification('preview_mfa_token');
  } else if (view === 'mfa-setup') {
    sessionState.currentRecoveryCodes = [
      'A7K2-9LP4', 'M4D8-2WJ9', 'R3X7-5QP1', 'H8V2-6ZN3',
      'C9B1-4TK8', 'E2F6-8YM5', 'P5J3-7LR2', 'K1W9-3HD6'
    ];
    document.getElementById('signInForm').classList.add('hidden');
    document.getElementById('authTabs').style.display = 'none';
    const setupView = document.getElementById('mfaSetupView');
    setupView.classList.remove('hidden');
    document.getElementById('mfaSecretCode').textContent = 'JBSWY3DPEHPK3PXP';
    document.getElementById('mfaQrImage').src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="white"/><rect x="10" y="10" width="30" height="30" fill="black"/><rect x="60" y="10" width="30" height="30" fill="black"/><rect x="10" y="60" width="30" height="30" fill="black"/><rect x="45" y="45" width="10" height="10" fill="black"/><rect x="70" y="70" width="20" height="20" fill="black"/></svg>';
    const grid = document.getElementById('recoveryCodesGrid');
    grid.innerHTML = '';
    sessionState.currentRecoveryCodes.forEach((code) => {
      const tag = document.createElement('div');
      tag.className = 'recovery-code-tag';
      tag.textContent = code;
      grid.appendChild(tag);
    });
  } else if (view === 'vault' || view === 'vault-reveal' || view === 'vault-versions') {
    // Generate populated visual dashboard state for Phase 4 screenshots
    sessionState.accessToken = 'preview_token';
    sessionState.user = { id: 'preview-usr', email: 'security.lead@securevault.io', mfaEnabled: true };
    document.getElementById('signInForm').classList.add('hidden');
    document.getElementById('authTabs').style.display = 'none';

    const wrapper = document.querySelector('.auth-wrapper');
    if (wrapper) wrapper.classList.add('vault-active');

    const dashboard = document.getElementById('vaultDashboard');
    dashboard.classList.remove('hidden');
    document.getElementById('dashUserEmail').textContent = sessionState.user.email;
    updateMfaStatusUI(true, 8);

    sessionState.vaultItems = [
      {
        id: 'item-aws-prod',
        title: 'AWS Production Root API Key',
        category: 'api_key',
        current_version: 2,
        access_level: 'owner',
        kek_version: 'kek_v2',
        updated_at: new Date().toISOString()
      },
      {
        id: 'item-stripe-key',
        title: 'Stripe Live Secret Key',
        category: 'api_key',
        current_version: 1,
        access_level: 'owner',
        kek_version: 'kek_v2',
        updated_at: new Date(Date.now() - 3600000).toISOString()
      },
      {
        id: 'item-db-pass',
        title: 'PostgreSQL Primary DB Password',
        category: 'password',
        current_version: 3,
        access_level: 'write',
        kek_version: 'kek_v2',
        updated_at: new Date(Date.now() - 86400000).toISOString()
      },
      {
        id: 'item-sec-note',
        title: 'Hardware Token Recovery Seed Note',
        category: 'note',
        current_version: 1,
        access_level: 'read',
        kek_version: 'kek_v2',
        updated_at: new Date(Date.now() - 172800000).toISOString()
      }
    ];

    document.getElementById('vaultItemCount').textContent = sessionState.vaultItems.length;
    document.getElementById('kekMetric').textContent = 'KEK v2';

    if (view === 'vault-reveal') {
      sessionState.revealedSecrets['item-aws-prod'] = 'DEMO_AWS_PROD_KEY_SECRET_998877_REVEALED';
    }

    renderVaultItems();

    if (view === 'vault-versions') {
      document.getElementById('versionModalItemTitle').textContent = 'AWS Production Root API Key';
      document.getElementById('vaultVersionsModal').classList.remove('hidden');
      const container = document.getElementById('versionsListContainer');
      container.innerHTML = `
        <div class="version-row">
          <div class="version-info">
            <span class="version-title">Version 2 (Active)</span>
            <span class="version-meta">Created ${new Date().toLocaleString()} • KEK: kek_v2 (aes-256-gcm)</span>
            <div style="font-family:var(--font-mono);font-size:11.5px;color:#38bdf8;margin-top:4px;">Payload: DEMO_AWS_PROD_KEY_SECRET_998877_REVEALED</div>
          </div>
          <button type="button" class="icon-btn" style="color:#34d399;border-color:rgba(16,185,129,0.3);">Active</button>
        </div>
        <div class="version-row">
          <div class="version-info">
            <span class="version-title">Version 1</span>
            <span class="version-meta">Created ${new Date(Date.now() - 86400000 * 3).toLocaleString()} • KEK: kek_v1 (aes-256-gcm)</span>
            <div style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-dim);margin-top:4px;">Payload: DEMO_PREVIOUS_KEY_ARCHIVED_V1</div>
          </div>
          <button type="button" class="icon-btn">🔍 View</button>
        </div>
      `;
    }
  } else if (view === 'files' || view === 'files-encrypting' || view === 'files-verified') {
    // Generate populated visual dashboard state for Phase 5 screenshots
    sessionState.accessToken = 'preview_token';
    sessionState.user = { id: 'preview-usr', email: 'security.lead@securevault.io', mfaEnabled: true };
    document.getElementById('signInForm').classList.add('hidden');
    document.getElementById('authTabs').style.display = 'none';

    const wrapper = document.querySelector('.auth-wrapper');
    if (wrapper) wrapper.classList.add('vault-active');

    const dashboard = document.getElementById('vaultDashboard');
    dashboard.classList.remove('hidden');
    document.getElementById('dashUserEmail').textContent = sessionState.user.email;
    updateMfaStatusUI(true, 8);

    sessionState.vaultItems = [
      { id: '1', title: 'DB Pass', category: 'password', current_version: 1, access_level: 'owner', kek_version: 'kek_v2' }
    ];
    document.getElementById('vaultItemCount').textContent = '1';
    document.getElementById('kekMetric').textContent = 'KEK v2';

    // Mock files for preview
    sessionState.files = [
      {
        id: 'file-backup-db',
        filename: 'production_database_backup_20261014.enc.sql.gz',
        mimeType: 'application/gzip',
        sizeBytes: 14680064,
        encryptedSizeBytes: 14680080,
        sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        kekVersion: 'kek_v2',
        algorithm: 'aes-256-gcm',
        createdAt: new Date().toISOString()
      },
      {
        id: 'file-pki-cert',
        filename: 'corporate_tls_intermediate_ca.p12',
        mimeType: 'application/x-pkcs12',
        sizeBytes: 4096,
        encryptedSizeBytes: 4112,
        sha256Checksum: '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03',
        kekVersion: 'kek_v2',
        algorithm: 'aes-256-gcm',
        createdAt: new Date(Date.now() - 3600000 * 2).toISOString()
      },
      {
        id: 'file-audit-report',
        filename: 'soc2_type2_security_audit_report.pdf',
        mimeType: 'application/pdf',
        sizeBytes: 2548000,
        encryptedSizeBytes: 2548016,
        sha256Checksum: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
        kekVersion: 'kek_v2',
        algorithm: 'aes-256-gcm',
        createdAt: new Date(Date.now() - 86400000).toISOString()
      }
    ];

    document.getElementById('vaultFileCount').textContent = sessionState.files.length;
    switchVaultView('files');
    renderFilesList();

    if (view === 'files-encrypting') {
      const card = document.getElementById('uploadProgressCard');
      card.classList.remove('hidden');
      document.getElementById('progressFileName').textContent = 'quarterly_audit_records.tar.gz';
      document.getElementById('progressFileSize').textContent = '8.4 MB';
      document.getElementById('progressBarFill').style.width = '74%';
      document.getElementById('progressStatusText').textContent = 'Encrypting... 74% (Streaming AES-256-GCM to MinIO)';
      document.getElementById('progressPercentText').textContent = '74%';
    } else if (view === 'files-verified') {
      const verifyBtn = document.getElementById('verify-btn-file-backup-db');
      if (verifyBtn) {
        verifyBtn.outerHTML = '<span class="verify-badge intact">✓ Intact & Authenticated</span>';
      }
    }
  }
});
