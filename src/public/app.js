// Global session state
let sessionState = {
  accessToken: null,
  refreshToken: null,
  user: null,
  tokenExpiresAt: null,
  countdownInterval: null
};

// Switch between Sign In and Register tabs
function switchTab(tab) {
  hideAlert();
  const tabSignIn = document.getElementById('tabSignIn');
  const tabRegister = document.getElementById('tabRegister');
  const signInForm = document.getElementById('signInForm');
  const registerForm = document.getElementById('registerForm');
  const vaultDashboard = document.getElementById('vaultDashboard');

  vaultDashboard.classList.add('hidden');

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

    // Success: activate session
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

    // Success alert, then switch to sign in
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

// Set active authenticated session
function setSession(data) {
  sessionState.accessToken = data.accessToken;
  sessionState.refreshToken = data.refreshToken;
  sessionState.user = data.user;
  // 15-minute expiration timestamp
  sessionState.tokenExpiresAt = Date.now() + 15 * 60 * 1000;

  // Update UI to show dashboard
  document.getElementById('signInForm').classList.add('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'none';
  
  const dashboard = document.getElementById('vaultDashboard');
  dashboard.classList.remove('hidden');
  document.getElementById('dashUserEmail').textContent = data.user.email;

  startJwtCountdown();
  showAlert('Authenticated with 15-minute sliding access token.', 'success');
}

// Countdown timer for 15-minute JWT
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

// Test protected endpoint
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

// Trigger token rotation manually from dashboard
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

// Handle Logout
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
    // Ignore network error on logout
  }

  sessionState = {
    accessToken: null,
    refreshToken: null,
    user: null,
    tokenExpiresAt: null,
    countdownInterval: null
  };

  document.getElementById('vaultDashboard').classList.add('hidden');
  document.getElementById('authTabs').style.display = 'flex';
  document.getElementById('apiOutput').classList.add('hidden');
  switchTab('signin');
  showAlert('Vault session terminated securely.', 'success');
}
