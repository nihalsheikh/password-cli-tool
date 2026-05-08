/**
 * Popup UI Controller for EigenVault - New Cyberpunk Design
 */
import { generatePassword, getPasswordStrengthScore } from '../core/password-gen.js';
// DOM Elements - Screens
const lockScreen = document.getElementById('lock-screen');
const setupScreen = document.getElementById('setup-screen');
const appScreen = document.getElementById('app-screen');
// Unlock Form
const unlockForm = document.getElementById('unlock-form');
const masterPasswordInput = document.getElementById('master-password');
const unlockBtn = document.getElementById('unlock-btn');
const unlockError = document.getElementById('unlock-error');
const forgotPasswordLink = document.getElementById('forgot-password-link');
const togglePasswordBtn = document.getElementById('toggle-password');
// MFA Area
const mfaArea = document.getElementById('mfa-area');
const mfaCodeInput = document.getElementById('mfa-code');
const verifyMfaBtn = document.getElementById('verify-mfa-btn');
// Reset Screen
const resetScreen = document.getElementById('reset-screen');
const resetWithRecoveryBtn = document.getElementById('reset-with-recovery');
const resetInputArea = document.getElementById('reset-input-area');
const resetCodeInput = document.getElementById('reset-code');
const verifyResetBtn = document.getElementById('verify-reset-btn');
const newPasswordArea = document.getElementById('new-password-area');
const newMasterPasswordInput = document.getElementById('new-master-password');
const confirmResetBtn = document.getElementById('confirm-reset-btn');
const backToUnlockBtn = document.getElementById('back-to-unlock');
// Setup Screen
const setupPasswordInput = document.getElementById('setup-password');
const setupPasswordConfirmInput = document.getElementById('setup-password-confirm');
const setupBtn = document.getElementById('setup-btn');
const setupError = document.getElementById('setup-error');
const strengthMeter = document.getElementById('password-strength');
// App Tabs
const tabVaultBtn = document.getElementById('tab-vault-btn');
const tabGenBtn = document.getElementById('tab-gen-btn');
const tabSettingsBtn = document.getElementById('tab-settings-btn');
const tabPanes = document.querySelectorAll('.tab-pane');
// Vault Tab
const searchInput = document.getElementById('search-input');
const matchingSection = document.getElementById('matching-section');
const matchingList = document.getElementById('matching-list');
const recentList = document.getElementById('recent-list');
const dashboardBtn = document.getElementById('dashboard-btn');
// Generator Tab (App Screen)
const appGeneratedPasswordEl = document.getElementById('generated-password');
const appRegenerateBtn = document.getElementById('regenerate-btn');
const appCopyGeneratedBtn = document.getElementById('copy-generated');
const appSaveGeneratedBtn = document.getElementById('save-generated-btn');
const appGenLength = document.getElementById('app-gen-length');
const appGenLengthVal = document.getElementById('app-gen-len-val');
// Quick Actions (Settings Tab)
const addBtn = document.getElementById('add-btn');
const viewAllBtn = document.getElementById('view-all-btn');
const lockBtn = document.getElementById('lock-btn');
const themeToggle = document.getElementById('theme-toggle');
// Quick Generator (Lock Screen)
const quickGenPass = document.getElementById('quick-gen-pass');
const quickGenLength = document.getElementById('gen-length');
const quickGenLengthVal = document.getElementById('gen-length-val');
const quickCopyBtn = document.getElementById('quick-copy-btn');
const quickRefreshBtn = document.getElementById('quick-refresh-btn');
/**
 * Send message to service worker
 */
function sendMessage(type, data = {}) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type, ...data }, (response) => {
            resolve(response);
        });
    });
}
/**
 * Initialize popup
 */
async function init() {
    // Load saved theme
    const pref = await chrome.storage.local.get(['eigen_theme']);
    const theme = pref['eigen_theme'] || 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    const initResponse = await sendMessage('CHECK_INITIALIZED');
    if (initResponse.initialized) {
        const unlockedResponse = await sendMessage('CHECK_UNLOCKED');
        if (unlockedResponse.unlocked) {
            await showMainScreen();
        }
        else {
            showUnlockScreen();
        }
    }
    else {
        showSetupScreen();
    }
    setupEventListeners();
    updateQuickGen();
    updateAppGen();
}
function showUnlockScreen() {
    lockScreen.classList.remove('hidden');
    setupScreen.classList.add('hidden');
    appScreen.classList.add('hidden');
    masterPasswordInput.focus();
}
function showSetupScreen() {
    lockScreen.classList.add('hidden');
    setupScreen.classList.remove('hidden');
    appScreen.classList.add('hidden');
    setupPasswordInput.focus();
}
async function showMainScreen() {
    // To avoid black screen, hide others explicitly and use a small delay for animation if needed
    lockScreen.classList.add('hidden');
    setupScreen.classList.add('hidden');
    appScreen.classList.remove('hidden');
    appScreen.style.display = 'flex';
    await loadMatchingCredentials();
    await loadRecentEntries();
    updateAppGen();
}
function updateQuickGen() {
    const length = parseInt(quickGenLength.value);
    quickGenLengthVal.textContent = length.toString();
    const password = generatePassword({ length });
    quickGenPass.textContent = password;
}
function updateAppGen() {
    const length = parseInt(appGenLength.value);
    appGenLengthVal.textContent = length.toString();
    const password = generatePassword({ length });
    appGeneratedPasswordEl.textContent = password;
}
/**
 * Event Listeners
 */
function setupEventListeners() {
    // Theme Toggle
    if (themeToggle) {
        themeToggle.addEventListener('click', async () => {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            await chrome.storage.local.set({ 'eigen_theme': next });
        });
    }
    // Unlock
    unlockBtn.addEventListener('click', handleUnlock);
    masterPasswordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter')
            handleUnlock();
    });
    togglePasswordBtn.addEventListener('click', () => {
        masterPasswordInput.type = masterPasswordInput.type === 'password' ? 'text' : 'password';
    });
    forgotPasswordLink.addEventListener('click', () => {
        unlockForm.classList.add('hidden');
        resetScreen.classList.remove('hidden');
    });
    // MFA
    verifyMfaBtn.addEventListener('click', handleMfaVerify);
    mfaCodeInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter')
            handleMfaVerify();
    });
    // Reset
    resetWithRecoveryBtn.addEventListener('click', () => {
        resetInputArea.classList.remove('hidden');
        resetCodeInput.placeholder = 'Recovery Key...';
        resetCodeInput.focus();
    });
    verifyResetBtn.addEventListener('click', () => {
        if (resetCodeInput.value.length > 10) {
            resetInputArea.classList.add('hidden');
            newPasswordArea.classList.remove('hidden');
            newMasterPasswordInput.focus();
        }
    });
    confirmResetBtn.addEventListener('click', handleResetConfirm);
    backToUnlockBtn.addEventListener('click', () => {
        resetScreen.classList.add('hidden');
        unlockForm.classList.remove('hidden');
    });
    // Setup
    setupBtn.addEventListener('click', handleSetup);
    setupPasswordInput.addEventListener('input', updateStrengthMeter);
    setupPasswordConfirmInput.addEventListener('input', updateStrengthMeter);
    // Tabs
    tabVaultBtn.addEventListener('click', () => switchTab('vault'));
    tabGenBtn.addEventListener('click', () => switchTab('gen'));
    tabSettingsBtn.addEventListener('click', () => switchTab('settings'));
    // Vault
    searchInput.addEventListener('input', handleSearch);
    dashboardBtn.addEventListener('click', openDashboard);
    // App Generator
    appRegenerateBtn.addEventListener('click', updateAppGen);
    appGenLength.addEventListener('input', updateAppGen);
    appCopyGeneratedBtn.addEventListener('click', async () => {
        const pass = appGeneratedPasswordEl.textContent;
        if (pass) {
            await navigator.clipboard.writeText(pass);
            appCopyGeneratedBtn.textContent = '✓';
            setTimeout(() => appCopyGeneratedBtn.textContent = '📋 COPY', 1500);
        }
    });
    appSaveGeneratedBtn.addEventListener('click', openDashboard);
    // Settings
    addBtn.addEventListener('click', openDashboard);
    viewAllBtn.addEventListener('click', openDashboard);
    lockBtn.addEventListener('click', lockVault);
    // Quick Gen
    quickGenLength.addEventListener('input', updateQuickGen);
    quickRefreshBtn.addEventListener('click', updateQuickGen);
    quickCopyBtn.addEventListener('click', async () => {
        const pass = quickGenPass.textContent;
        if (pass && pass !== '••••••••••••••••') {
            await navigator.clipboard.writeText(pass);
            quickCopyBtn.textContent = '✓';
            setTimeout(() => { quickCopyBtn.textContent = '📋'; }, 1500);
        }
    });
}
/**
 * Handlers
 */
async function handleUnlock() {
    const password = masterPasswordInput.value;
    if (!password)
        return;
    unlockBtn.disabled = true;
    const response = await sendMessage('UNLOCK_WITH_PASSWORD', { masterPassword: password });
    if (response.success) {
        if (response.mfaRequired) {
            unlockBtn.classList.add('hidden');
            mfaArea.classList.remove('hidden');
            mfaCodeInput.focus();
        }
        else {
            await showMainScreen();
        }
    }
    else {
        showError(unlockError, response.error || 'ACCESS DENIED');
    }
    unlockBtn.disabled = false;
}
async function handleMfaVerify() {
    const code = mfaCodeInput.value;
    if (code.length !== 6)
        return;
    verifyMfaBtn.disabled = true;
    const response = await sendMessage('VERIFY_MFA_CODE', { code });
    if (response.success) {
        await showMainScreen();
    }
    else {
        showError(unlockError, 'INVALID CODE');
        mfaCodeInput.value = '';
    }
    verifyMfaBtn.disabled = false;
}
async function handleSetup() {
    const password = setupPasswordInput.value;
    if (password !== setupPasswordConfirmInput.value)
        return;
    setupBtn.disabled = true;
    const response = await sendMessage('INITIALIZE_VAULT', { masterPassword: password });
    if (response.success) {
        await sendMessage('UNLOCK_WITH_PASSWORD', { masterPassword: password });
        await showMainScreen();
    }
    else {
        showError(setupError, 'SETUP FAILED');
    }
    setupBtn.disabled = false;
}
async function handleResetConfirm() {
    const recoveryKey = resetCodeInput.value;
    const newPassword = newMasterPasswordInput.value;
    if (newPassword.length < 8)
        return;
    const response = await sendMessage('RESET_MASTER_PASSWORD', { recoveryKey, newPassword });
    if (response.success) {
        location.reload();
    }
    else {
        alert('RESET FAILED');
    }
}
function switchTab(name) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`tab-${name}-btn`)?.classList.add('active');
    tabPanes.forEach(p => p.classList.remove('active'));
    document.getElementById(`tab-${name}`)?.classList.add('active');
}
async function loadMatchingCredentials() {
    const response = await sendMessage('GET_MATCHING_ENTRIES');
    if (!response.matches || response.matches.length === 0) {
        matchingSection.classList.add('hidden');
        return;
    }
    matchingList.innerHTML = response.matches.map((entry) => `
    <div class="vault-item" data-user="${entry.username}" data-pass="${entry.password}">
      <div class="vault-item-name">${escapeHtml(entry.name || entry.url)}</div>
      <div class="vault-item-user">${escapeHtml(entry.username)}</div>
    </div>
  `).join('');
    matchingList.querySelectorAll('.vault-item').forEach(item => {
        item.addEventListener('click', () => fillCredentials(item));
    });
    matchingSection.classList.remove('hidden');
}
async function loadRecentEntries() {
    const response = await sendMessage('GET_ENTRIES');
    if (!response.entries || response.entries.length === 0) {
        recentList.innerHTML = '<p class="brand-sub" style="font-size: 10px; opacity: 0.5;">No entries found</p>';
        return;
    }
    const recent = response.entries.slice(-5).reverse();
    recentList.innerHTML = recent.map((entry) => `
    <div class="vault-item" data-user="${entry.username}" data-pass="${entry.password}">
      <div class="vault-item-name">${escapeHtml(entry.name || entry.url)}</div>
      <div class="vault-item-user">${escapeHtml(entry.username)}</div>
    </div>
  `).join('');
    recentList.querySelectorAll('.vault-item').forEach(item => {
        item.addEventListener('click', () => fillCredentials(item));
    });
}
async function fillCredentials(item) {
    const username = item.dataset.user;
    const password = item.dataset.pass;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, { type: 'FILL_CREDENTIALS', username, password });
        window.close();
    }
}
function updateStrengthMeter() {
    const password = setupPasswordInput.value;
    const strength = getPasswordStrengthScore(password);
    strengthMeter.setAttribute('data-strength', strength.score.toString());
    setupBtn.disabled = password !== setupPasswordConfirmInput.value || strength.score < 4;
}
function handleSearch() {
    const query = searchInput.value.toLowerCase();
    document.querySelectorAll('#recent-list .vault-item').forEach(item => {
        const text = item.textContent?.toLowerCase() || '';
        item.style.display = text.includes(query) ? 'block' : 'none';
    });
}
function lockVault() {
    sendMessage('LOCK_VAULT').then(() => location.reload());
}
function openDashboard() {
    chrome.runtime.openOptionsPage();
}
function showError(el, msg) {
    el.textContent = msg;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 3000);
}
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
init();
//# sourceMappingURL=popup.js.map