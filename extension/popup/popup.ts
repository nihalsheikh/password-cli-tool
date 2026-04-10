/**
 * Popup UI Controller for EigenVault
 */

import { generatePassword, isPasswordStrong, getPasswordStrengthScore } from '../core/password-gen';

// DOM Elements
const lockScreen = document.getElementById('lock-screen')!;
const mainScreen = document.getElementById('main-screen')!;
const unlockForm = document.getElementById('unlock-form')!;
const setupForm = document.getElementById('setup-form')!;
const masterPasswordInput = document.getElementById('master-password') as HTMLInputElement;
const setupPasswordInput = document.getElementById('setup-password') as HTMLInputElement;
const setupPasswordConfirmInput = document.getElementById('setup-password-confirm') as HTMLInputElement;
const unlockBtn = document.getElementById('unlock-btn') as HTMLButtonElement;
const setupBtn = document.getElementById('setup-btn') as HTMLButtonElement;
const biometricBtn = document.getElementById('biometric-btn') as HTMLButtonElement;
const biometricSection = document.getElementById('biometric-section')!;
const unlockError = document.getElementById('unlock-error')!;
const setupError = document.getElementById('setup-error')!;
const togglePasswordBtn = document.getElementById('toggle-password') as HTMLButtonElement;
const strengthMeter = document.getElementById('password-strength') as HTMLDivElement;

// Main screen elements
const generateBtn = document.getElementById('generate-btn') as HTMLButtonElement;
const addBtn = document.getElementById('add-btn') as HTMLButtonElement;
const dashboardBtn = document.getElementById('dashboard-btn') as HTMLButtonElement;
const lockBtn = document.getElementById('lock-btn') as HTMLButtonElement;
const searchInput = document.getElementById('search-input') as HTMLInputElement;
const matchingSection = document.getElementById('matching-section')!;
const matchingList = document.getElementById('matching-list')!;
const recentList = document.getElementById('recent-list')!;
const viewAllBtn = document.getElementById('view-all-btn') as HTMLButtonElement;

// Generated password section
const generatedSection = document.getElementById('generated-section')!;
const generatedPasswordEl = document.getElementById('generated-password')!;
const strengthValueEl = document.getElementById('strength-value')!;
const copyGeneratedBtn = document.getElementById('copy-generated') as HTMLButtonElement;
const regenerateBtn = document.getElementById('regenerate-btn') as HTMLButtonElement;
const saveGeneratedBtn = document.getElementById('save-generated-btn') as HTMLButtonElement;
const closeGeneratedBtn = document.getElementById('close-generated') as HTMLButtonElement;

// Modal elements
const addModal = document.getElementById('add-modal')!;
const modalTitle = document.getElementById('modal-title')!;
const closeModalBtn = document.getElementById('close-modal') as HTMLButtonElement;
const addForm = document.getElementById('add-form') as HTMLFormElement;
const entryUrlInput = document.getElementById('entry-url') as HTMLInputElement;
const entryUsernameInput = document.getElementById('entry-username') as HTMLInputElement;
const entryPasswordInput = document.getElementById('entry-password') as HTMLInputElement;
const entryNoteInput = document.getElementById('entry-note') as HTMLTextAreaElement;
const generateInlineBtn = document.getElementById('generate-inline') as HTMLButtonElement;
const toggleEntryPasswordBtn = document.getElementById('toggle-entry-password') as HTMLButtonElement;
const cancelBtn = document.getElementById('cancel-btn') as HTMLButtonElement;

// State
let currentGeneratedPassword = '';
let isEditing = false;
let editIndex = -1;

/**
 * Send message to service worker
 */
function sendMessage(type: string, data: Record<string, unknown> = {}): Promise<unknown> {
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
  const response = await sendMessage('CHECK_INITIALIZED') as { initialized: boolean };

  if (response.initialized) {
    showUnlockForm();
  } else {
    showSetupForm();
  }

  // Check WebAuthn support
  const webauthnResponse = await sendMessage('CHECK_WEBAUTHN') as { supported: boolean };
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
    if (e.key === 'Enter') handleUnlock();
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

  const response = await sendMessage('UNLOCK_WITH_PASSWORD', { masterPassword: password }) as { success: boolean; error?: string };

  if (response.success) {
    showMainScreen();
  } else {
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
  const response = await sendMessage('UNLOCK_WITH_BIOMETRIC') as { success: boolean; error?: string };

  if (response.success) {
    showMainScreen();
  } else {
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

  const response = await sendMessage('INITIALIZE_VAULT', { masterPassword: password }) as { success: boolean };

  if (response.success) {
    // Auto-unlock after setup
    await sendMessage('UNLOCK_WITH_PASSWORD', { masterPassword: password });
    showMainScreen();
  } else {
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

  const strengthText = strengthMeter.querySelector('.strength-text')!;
  strengthText.textContent = labels[strength.score];
  strengthText.style.color = colors[strength.score];

  // Enable setup button only if passwords match and strong enough
  setupBtn.disabled = password !== confirm || strength.score < 4;
}

/**
 * Show error message
 */
function showError(element: HTMLElement, message: string) {
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
  } catch {
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
  const response = await sendMessage('GET_MATCHING_ENTRIES') as { matches?: Array<{ url: string; username: string; name: string }>; error?: string };

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
      fillCredentials(item as HTMLElement);
    });
    item.querySelector('.copy-btn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      copyCredentials(item as HTMLElement);
    });
    item.addEventListener('click', () => fillCredentials(item as HTMLElement));
  });

  matchingSection.classList.remove('hidden');
}

/**
 * Load recent entries
 */
async function loadRecentEntries() {
  const response = await sendMessage('GET_ENTRIES') as { entries?: Array<{ url: string; username: string; name: string; password: string }>; error?: string };

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
async function fillCredentials(item: HTMLElement) {
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
async function copyCredentials(item: HTMLElement) {
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

  const response = await sendMessage('SEARCH_ENTRIES', { query }) as { entries?: Array<{ url: string; username: string; name: string; password: string }> };

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
function openModal(title: string) {
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
async function handleFormSubmit(e: Event) {
  e.preventDefault();

  const entry = {
    name: '',
    url: entryUrlInput.value,
    username: entryUsernameInput.value,
    password: entryPasswordInput.value,
    note: entryNoteInput.value,
  };

  const response = await sendMessage('ADD_ENTRY', { entry }) as { success: boolean; error?: string };

  if (response.success) {
    closeModal();
    await loadMatchingCredentials();
    await loadRecentEntries();
  } else {
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
function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Initialize on load
init();
