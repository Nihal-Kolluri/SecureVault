// Global session state
let sessionState = {
  accessToken: null,
  refreshToken: null,
  user: null,
  tokenExpiresAt: null,
  countdownInterval: null,
  mfaPendingToken: null,
  pendingSetupToken: null,
  currentRecoveryCodes: []
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

  const dashboard = document.getElementById('vaultDashboard');
  dashboard.classList.remove('hidden');
  document.getElementById('dashUserEmail').textContent = data.user.email;

  updateMfaStatusUI(data.user.mfaEnabled);
  startJwtCountdown();
  fetchMfaStatus();
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
    currentRecoveryCodes: []
  };

  document.getElementById('vaultDashboard').classList.add('hidden');
  document.getElementById('mfaVerifyView').classList.add('hidden');
  document.getElementById('mfaSetupView').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'flex';
  document.getElementById('apiOutput').classList.add('hidden');
  switchTab('signin');
  showAlert('Vault session terminated securely.', 'success');
}

// Initialize on DOM load
window.addEventListener('DOMContentLoaded', () => {
  initSixBoxes();
});
