/**
 * Popup UI Controller for EigenVault
 */
import { generatePassword, isPasswordStrong, getPasswordStrengthScore } from '../core/password-gen.js';
// DOM Elements
const lockScreen = document.getElementById('lock-screen');
const mainScreen = document.getElementById('main-screen');
const unlockForm = document.getElementById('unlock-form');
const setupForm = document.getElementById('setup-form');
const masterPasswordInput = document.getElementById('master-password');
const setupPasswordInput = document.getElementById('setup-password');
const setupPasswordConfirmInput = document.getElementById('setup-password-confirm');
const unlockBtn = document.getElementById('unlock-btn');
const setupBtn = document.getElementById('setup-btn');
const biometricBtn = document.getElementById('biometric-btn');
const biometricSection = document.getElementById('biometric-section');
const unlockError = document.getElementById('unlock-error');
const setupError = document.getElementById('setup-error');
const togglePasswordBtn = document.getElementById('toggle-password');
const strengthMeter = document.getElementById('password-strength');
// Main screen elements
const generateBtn = document.getElementById('generate-btn');
const addBtn = document.getElementById('add-btn');
const dashboardBtn = document.getElementById('dashboard-btn');
const lockBtn = document.getElementById('lock-btn');
const searchInput = document.getElementById('search-input');
const matchingSection = document.getElementById('matching-section');
const matchingList = document.getElementById('matching-list');
const recentList = document.getElementById('recent-list');
const viewAllBtn = document.getElementById('view-all-btn');
// Generated password section
const generatedSection = document.getElementById('generated-section');
const generatedPasswordEl = document.getElementById('generated-password');
const strengthValueEl = document.getElementById('strength-value');
const copyGeneratedBtn = document.getElementById('copy-generated');
const regenerateBtn = document.getElementById('regenerate-btn');
const saveGeneratedBtn = document.getElementById('save-generated-btn');
const closeGeneratedBtn = document.getElementById('close-generated');
// Modal elements
const addModal = document.getElementById('add-modal');
const modalTitle = document.getElementById('modal-title');
const closeModalBtn = document.getElementById('close-modal');
const addForm = document.getElementById('add-form');
const entryUrlInput = document.getElementById('entry-url');
const entryUsernameInput = document.getElementById('entry-username');
const entryPasswordInput = document.getElementById('entry-password');
const entryNoteInput = document.getElementById('entry-note');
const generateInlineBtn = document.getElementById('generate-inline');
const toggleEntryPasswordBtn = document.getElementById('toggle-entry-password');
const cancelBtn = document.getElementById('cancel-btn');
// State
let currentGeneratedPassword = '';
let isEditing = false;
let editIndex = -1;
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
    // Check if vault is initialized
    const response = await sendMessage('CHECK_INITIALIZED');
    if (response.initialized) {
        showUnlockForm();
    }
    else {
        showSetupForm();
    }
    // Check WebAuthn support
    const webauthnResponse = await sendMessage('CHECK_WEBAUTHN');
    if (webauthnResponse.supported) {
        biometricSection.classList.remove('hidden');
    }
    // Set up event listeners
    setupEventListeners();
}
/**
 * Show unlock form
 */
function showUnlockForm() {
    unlockForm.classList.remove('hidden');
    setupForm.classList.add('hidden');
    masterPasswordInput.value = '';
    masterPasswordInput.focus();
}
/**
 * Show setup form
 */
function showSetupForm() {
    unlockForm.classList.add('hidden');
    setupForm.classList.remove('hidden');
    setupPasswordInput.value = '';
    setupPasswordConfirmInput.value = '';
    setupPasswordInput.focus();
}
/**
 * Show main screen
 */
async function showMainScreen() {
    lockScreen.classList.add('hidden');
    mainScreen.classList.remove('hidden');
    // Load matching credentials for current site
    await loadMatchingCredentials();
    // Load recent entries
    await loadRecentEntries();
}
/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Unlock button
    unlockBtn.addEventListener('click', handleUnlock);
    masterPasswordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter')
            handleUnlock();
    });
    // Setup button
    setupBtn.addEventListener('click', handleSetup);
    setupPasswordInput.addEventListener('input', updateStrengthMeter);
    setupPasswordConfirmInput.addEventListener('input', updateStrengthMeter);
    // Toggle password visibility
    togglePasswordBtn.addEventListener('click', () => {
        const type = masterPasswordInput.type === 'password' ? 'text' : 'password';
        masterPasswordInput.type = type;
    });
    // Biometric unlock
    biometricBtn.addEventListener('click', handleBiometricUnlock);
    // Main screen actions
    generateBtn.addEventListener('click', showGeneratedPassword);
    addBtn.addEventListener('click', () => openModal('Add Password'));
    dashboardBtn.addEventListener('click', openDashboard);
    lockBtn.addEventListener('click', lockVault);
    viewAllBtn.addEventListener('click', openDashboard);
    // Search
    searchInput.addEventListener('input', handleSearch);
    // Generated password
    copyGeneratedBtn.addEventListener('click', copyGeneratedPassword);
    regenerateBtn.addEventListener('click', showGeneratedPassword);
    saveGeneratedBtn.addEventListener('click', saveGeneratedPassword);
    closeGeneratedBtn.addEventListener('click', () => generatedSection.classList.add('hidden'));
    // Modal
    closeModalBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);
    addForm.addEventListener('submit', handleFormSubmit);
    generateInlineBtn.addEventListener('click', generateInlinePassword);
    toggleEntryPasswordBtn.addEventListener('click', () => {
        const type = entryPasswordInput.type === 'password' ? 'text' : 'password';
        entryPasswordInput.type = type;
    });
}
/**
 * Handle vault unlock with password
 */
async function handleUnlock() {
    const password = masterPasswordInput.value;
    if (!password) {
        showError(unlockError, 'Please enter your master password');
        return;
    }
    unlockBtn.disabled = true;
    unlockBtn.textContent = 'Unlocking...';
    const response = await sendMessage('UNLOCK_WITH_PASSWORD', { masterPassword: password });
    if (response.success) {
        showMainScreen();
    }
    else {
        showError(unlockError, response.error || 'Failed to unlock');
    }
    unlockBtn.disabled = false;
    unlockBtn.textContent = 'Unlock';
}
/**
 * Handle biometric unlock
 */
async function handleBiometricUnlock() {
    biometricBtn.disabled = true;
    biometricBtn.textContent = 'Authenticating...';
    // First need to unlock with password to get credential ID
    // This is a simplified flow - full implementation would store credential ID
    const response = await sendMessage('UNLOCK_WITH_BIOMETRIC');
    if (response.success) {
        showMainScreen();
    }
    else {
        showError(unlockError, 'Biometric unlock failed. Please use password.');
    }
    biometricBtn.disabled = false;
    biometricBtn.textContent = '👆 Use Biometric';
}
/**
 * Handle vault setup
 */
async function handleSetup() {
    const password = setupPasswordInput.value;
    const confirm = setupPasswordConfirmInput.value;
    if (!password) {
        showError(setupError, 'Please enter a password');
        return;
    }
    if (password !== confirm) {
        showError(setupError, 'Passwords do not match');
        return;
    }
    const strength = getPasswordStrengthScore(password);
    if (strength.score < 4) {
        showError(setupError, 'Please create a stronger password (use uppercase, lowercase, numbers, and symbols)');
        return;
    }
    setupBtn.disabled = true;
    setupBtn.textContent = 'Creating...';
    const response = await sendMessage('INITIALIZE_VAULT', { masterPassword: password });
    if (response.success) {
        // Auto-unlock after setup
        await sendMessage('UNLOCK_WITH_PASSWORD', { masterPassword: password });
        showMainScreen();
    }
    else {
        showError(setupError, 'Failed to create vault');
    }
    setupBtn.disabled = false;
    setupBtn.textContent = 'Create Vault';
}
/**
 * Update password strength meter
 */
function updateStrengthMeter() {
    const password = setupPasswordInput.value;
    const confirm = setupPasswordConfirmInput.value;
    if (!password) {
        strengthMeter.removeAttribute('data-strength');
        setupBtn.disabled = true;
        return;
    }
    const strength = getPasswordStrengthScore(password);
    strengthMeter.setAttribute('data-strength', strength.score.toString());
    const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
    const colors = ['', 'var(--danger)', 'var(--warning)', '#84cc16', 'var(--success)', 'var(--primary)'];
    const strengthText = strengthMeter.querySelector('.strength-text');
    strengthText.textContent = labels[strength.score];
    strengthText.style.color = colors[strength.score];
    // Enable setup button only if passwords match and strong enough
    setupBtn.disabled = password !== confirm || strength.score < 4;
}
/**
 * Show error message
 */
function showError(element, message) {
    element.textContent = message;
    element.classList.remove('hidden');
    setTimeout(() => {
        element.classList.add('hidden');
    }, 5000);
}
/**
 * Generate and display a password
 */
function showGeneratedPassword() {
    currentGeneratedPassword = generatePassword({ length: 16 });
    const strong = isPasswordStrong(currentGeneratedPassword);
    generatedPasswordEl.textContent = currentGeneratedPassword;
    strengthValueEl.textContent = strong ? 'Strong' : 'Weak';
    strengthValueEl.style.color = strong ? 'var(--success)' : 'var(--warning)';
    generatedSection.classList.remove('hidden');
}
/**
 * Copy generated password to clipboard
 */
async function copyGeneratedPassword() {
    try {
        await navigator.clipboard.writeText(currentGeneratedPassword);
        copyGeneratedBtn.textContent = '✓';
        setTimeout(() => {
            copyGeneratedBtn.textContent = '📋';
        }, 1500);
    }
    catch {
        // Fallback for extension context
        await sendMessage('COPY_TO_CLIPBOARD', { text: currentGeneratedPassword });
    }
}
/**
 * Save generated password
 */
function saveGeneratedPassword() {
    openModal('Save Password');
    entryPasswordInput.value = currentGeneratedPassword;
    generatedSection.classList.add('hidden');
}
/**
 * Load matching credentials for current site
 */
async function loadMatchingCredentials() {
    const response = await sendMessage('GET_MATCHING_ENTRIES');
    if (response.error || !response.matches || response.matches.length === 0) {
        matchingSection.classList.add('hidden');
        return;
    }
    matchingList.innerHTML = response.matches.map((entry, index) => `
    <div class="credential-item" data-index="${index}" data-url="${entry.url}" data-username="${entry.username}">
      <div class="credential-icon">🔐</div>
      <div class="credential-info">
        <div class="credential-name">${escapeHtml(entry.name || entry.url)}</div>
        <div class="credential-username">${escapeHtml(entry.username)}</div>
      </div>
      <div class="credential-actions">
        <button class="fill-btn" title="Fill">⚡</button>
        <button class="copy-btn" title="Copy">📋</button>
      </div>
    </div>
  `).join('');
    // Add event listeners
    matchingList.querySelectorAll('.credential-item').forEach((item) => {
        item.querySelector('.fill-btn')?.addEventListener('click', (e) => {
            e.stopPropagation();
            fillCredentials(item);
        });
        item.querySelector('.copy-btn')?.addEventListener('click', (e) => {
            e.stopPropagation();
            copyCredentials(item);
        });
        item.addEventListener('click', () => fillCredentials(item));
    });
    matchingSection.classList.remove('hidden');
}
/**
 * Load recent entries
 */
async function loadRecentEntries() {
    const response = await sendMessage('GET_ENTRIES');
    if (response.error || !response.entries) {
        recentList.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No passwords stored</p>';
        return;
    }
    const recent = response.entries.slice(-5).reverse();
    recentList.innerHTML = recent.map((entry, index) => `
    <div class="credential-item">
      <div class="credential-icon">🔐</div>
      <div class="credential-info">
        <div class="credential-name">${escapeHtml(entry.name || entry.url)}</div>
        <div class="credential-username">${escapeHtml(entry.username)}</div>
      </div>
      <div class="credential-actions">
        <button class="copy-btn" title="Copy">📋</button>
      </div>
    </div>
  `).join('');
    recentList.querySelectorAll('.copy-btn').forEach((btn, index) => {
        btn.addEventListener('click', () => {
            const password = recent[index].password;
            navigator.clipboard.writeText(password);
            btn.textContent = '✓';
            setTimeout(() => { btn.textContent = '📋'; }, 1500);
        });
    });
}
/**
 * Fill credentials on page
 */
async function fillCredentials(item) {
    const url = item.dataset.url;
    const username = item.dataset.username;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, {
            type: 'FILL_CREDENTIALS',
            username,
            password: '', // Would need to decrypt - simplified here
        });
    }
}
/**
 * Copy credentials password
 */
async function copyCredentials(item) {
    // Would need to get password from background
    // Simplified for now
}
/**
 * Handle search
 */
async function handleSearch() {
    const query = searchInput.value.trim();
    if (!query) {
        await loadRecentEntries();
        return;
    }
    const response = await sendMessage('SEARCH_ENTRIES', { query });
    if (!response.entries || response.entries.length === 0) {
        recentList.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No results found</p>';
        return;
    }
    recentList.innerHTML = response.entries.map((entry) => `
    <div class="credential-item">
      <div class="credential-icon">🔐</div>
      <div class="credential-info">
        <div class="credential-name">${escapeHtml(entry.name || entry.url)}</div>
        <div class="credential-username">${escapeHtml(entry.username)}</div>
      </div>
      <div class="credential-actions">
        <button class="copy-btn" title="Copy">📋</button>
      </div>
    </div>
  `).join('');
}
/**
 * Open modal
 */
function openModal(title) {
    modalTitle.textContent = title;
    addModal.classList.remove('hidden');
    entryUrlInput.focus();
    isEditing = false;
}
/**
 * Close modal
 */
function closeModal() {
    addModal.classList.add('hidden');
    addForm.reset();
}
/**
 * Generate inline password
 */
function generateInlinePassword() {
    const password = generatePassword({ length: 16 });
    entryPasswordInput.value = password;
    entryPasswordInput.type = 'text';
}
/**
 * Handle form submit
 */
async function handleFormSubmit(e) {
    e.preventDefault();
    const entry = {
        name: '',
        url: entryUrlInput.value,
        username: entryUsernameInput.value,
        password: entryPasswordInput.value,
        note: entryNoteInput.value,
    };
    const response = await sendMessage('ADD_ENTRY', { entry });
    if (response.success) {
        closeModal();
        await loadMatchingCredentials();
        await loadRecentEntries();
    }
    else {
        alert(response.error || 'Failed to save');
    }
}
/**
 * Lock vault
 */
async function lockVault() {
    await sendMessage('LOCK_VAULT');
    location.reload();
}
/**
 * Open dashboard
 */
function openDashboard() {
    chrome.runtime.openOptionsPage();
}
/**
 * Escape HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
// Initialize on load
init();
//# sourceMappingURL=popup.js.map