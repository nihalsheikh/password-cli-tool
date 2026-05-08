/**
 * Dashboard UI Controller for EigenVault - Redesigned
 */

import { generatePassword, isPasswordStrong, getPasswordStrengthScore } from '../core/password-gen.js';

// State
let allEntries: Array<{ name: string; url: string; username: string; password: string; note: string }> = [];

// DOM Elements - Navigation
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const themeToggle = document.getElementById('theme-toggle') as HTMLButtonElement;

// All Passwords View
const passwordTbody = document.getElementById('password-tbody') as HTMLTableSectionElement;
const passwordCount = document.getElementById('password-count') as HTMLElement;
const globalSearch = document.getElementById('global-search') as HTMLInputElement;
const addNewBtn = document.getElementById('add-new-btn') as HTMLButtonElement;

// Generator View
const genPasswordEl = document.getElementById('gen-password') as HTMLElement;
const genCopyBtn = document.getElementById('gen-copy') as HTMLButtonElement;
const genRegenerateBtn = document.getElementById('gen-regenerate') as HTMLButtonElement;
const genLengthSlider = document.getElementById('gen-length') as HTMLInputElement;
const lengthValue = document.getElementById('length-value') as HTMLElement;
const optUppercase = document.getElementById('opt-uppercase') as HTMLInputElement;
const optLowercase = document.getElementById('opt-lowercase') as HTMLInputElement;
const optDigits = document.getElementById('opt-digits') as HTMLInputElement;
const optSpecial = document.getElementById('opt-special') as HTMLInputElement;

// Settings View
const autolockTimeout = document.getElementById('autolock-timeout') as HTMLSelectElement;
const setupBiometricBtn = document.getElementById('setup-biometric') as HTMLButtonElement;
const exportBtnSettings = document.getElementById('export-btn-settings') as HTMLButtonElement;
const settingsImportInput = document.getElementById('settings-import') as HTMLInputElement;
const resetVaultBtn = document.getElementById('reset-vault') as HTMLButtonElement;
const setupRecoveryKeyBtn = document.getElementById('setup-recovery-key') as HTMLButtonElement;
const setupTotpBtn = document.getElementById('setup-totp') as HTMLButtonElement;
const setupOtpBtn = document.getElementById('setup-otp') as HTMLButtonElement;
const lockVaultBtn = document.getElementById('lock-vault-btn') as HTMLButtonElement;

// Entry Modal
const entryModal = document.getElementById('entry-modal') as HTMLElement;
const modalTitle = document.getElementById('modal-title')!;
const modalClose = document.getElementById('modal-close') as HTMLButtonElement;
const modalCancel = document.getElementById('modal-cancel') as HTMLButtonElement;
const entryForm = document.getElementById('entry-form') as HTMLFormElement;
const editIndexInput = document.getElementById('edit-index') as HTMLInputElement;
const entryNameInput = document.getElementById('entry-name') as HTMLInputElement;
const entryUrlInput = document.getElementById('entry-url') as HTMLInputElement;
const entryUsernameInput = document.getElementById('entry-username') as HTMLInputElement;
const entryPasswordInput = document.getElementById('entry-password') as HTMLInputElement;
const entryNoteInput = document.getElementById('entry-note') as HTMLTextAreaElement;
const togglePasswordBtn = document.getElementById('toggle-password') as HTMLButtonElement;
const generatePasswordBtn = document.getElementById('generate-password') as HTMLButtonElement;

/**
 * Send message to service worker
 */
function sendMessage(type: string, data: Record<string, unknown> = {}): Promise<any> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...data }, (response) => {
      resolve(response);
    });
  });
}

/**
 * Initialize dashboard
 */
async function init() {
  // Load Theme
  const pref = await chrome.storage.local.get(['eigen_theme']);
  const theme = pref['eigen_theme'] || 'dark';
  document.documentElement.setAttribute('data-theme', theme);

  setupNavigation();
  setupEventListeners();
  await loadEntries();
  updateGenerator();
}

function setupNavigation() {
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');

      const targetView = (item as HTMLElement).dataset.view;
      views.forEach(v => v.classList.remove('active'));
      document.getElementById(`view-${targetView}`)?.classList.add('active');
    });
  });
}

function setupEventListeners() {
  // Theme Toggle
  themeToggle.addEventListener('click', async () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    await chrome.storage.local.set({ 'eigen_theme': next });
  });

  // Global Actions
  globalSearch.addEventListener('input', handleSearch);
  addNewBtn.addEventListener('click', () => openEntryModal());
  lockVaultBtn.addEventListener('click', lockVault);

  // Generator
  genRegenerateBtn.addEventListener('click', updateGenerator);
  genCopyBtn.addEventListener('click', copyToClipboard);
  genLengthSlider.addEventListener('input', () => {
    lengthValue.textContent = genLengthSlider.value;
    updateGenerator();
  });
  [optUppercase, optLowercase, optDigits, optSpecial].forEach(cb => {
    cb.addEventListener('change', updateGenerator);
  });

  // Modal
  modalClose.addEventListener('click', closeEntryModal);
  modalCancel.addEventListener('click', closeEntryModal);
  entryForm.addEventListener('submit', handleFormSubmit);
  togglePasswordBtn.addEventListener('click', () => {
    entryPasswordInput.type = entryPasswordInput.type === 'password' ? 'text' : 'password';
  });
  generatePasswordBtn.addEventListener('click', () => {
    entryPasswordInput.value = generatePassword({ length: 16 });
    entryPasswordInput.type = 'text';
  });

  // Settings
  autolockTimeout.addEventListener('change', async () => {
    await sendMessage('SET_AUTO_LOCK', { minutes: parseInt(autolockTimeout.value) });
  });
  setupRecoveryKeyBtn.addEventListener('click', handleSetupRecoveryKey);
  setupTotpBtn.addEventListener('click', () => alert('Authenticator setup coming soon (Beta)'));
  setupOtpBtn.addEventListener('click', () => alert('Email verification coming soon (Beta)'));
  setupBiometricBtn.addEventListener('click', () => alert('Biometric testing in progress'));
  exportBtnSettings.addEventListener('click', handleExport);
  settingsImportInput.addEventListener('change', handleImport);
  resetVaultBtn.addEventListener('click', handleResetVault);
}

async function loadEntries() {
  const response = await sendMessage('GET_ENTRIES');
  if (response.error) {
    location.href = '../popup/popup.html';
    return;
  }
  allEntries = response.entries || [];
  renderEntries(allEntries);
}

function renderEntries(entries: any[]) {
  passwordCount.textContent = entries.length.toString();
  if (entries.length === 0) {
    passwordTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 48px; color: var(--text-muted);">No records found in vault.</td></tr>';
    return;
  }

  passwordTbody.innerHTML = entries.map((entry, index) => `
    <tr>
      <td>
        <div class="site-cell">
          <div class="site-icon">🔐</div>
          <div>
            <div class="site-name">${escapeHtml(entry.name || 'Account')}</div>
            <div class="site-url">${escapeHtml(entry.url)}</div>
          </div>
        </div>
      </td>
      <td class="mono-cell">${escapeHtml(entry.username)}</td>
      <td class="mono-cell">${escapeHtml(entry.url)}</td>
      <td><span class="success-text" style="font-size: 10px; font-weight: 700;">ENCRYPTED</span></td>
      <td style="text-align: right;">
        <button class="icon-btn" title="Copy" onclick="window.copyEntry(${index})">📋</button>
        <button class="icon-btn" title="Edit" onclick="window.editEntry(${index})">✏️</button>
        <button class="icon-btn" title="Delete" onclick="window.deleteEntry(${index})">🗑️</button>
      </td>
    </tr>
  `).join('');
}

function updateGenerator() {
  const options = {
    length: parseInt(genLengthSlider.value),
    useUppercase: optUppercase.checked,
    useLowercase: optLowercase.checked,
    useDigits: optDigits.checked,
    useSpecial: optSpecial.checked
  };
  const pass = generatePassword(options);
  genPasswordEl.textContent = pass;
}

async function copyToClipboard() {
  const pass = genPasswordEl.textContent;
  if (pass && pass !== '••••••••••••••••') {
    await navigator.clipboard.writeText(pass);
    genCopyBtn.textContent = '✓';
    setTimeout(() => genCopyBtn.textContent = '📋', 1500);
  }
}

function openEntryModal(index?: number) {
  if (index !== undefined) {
    const entry = allEntries[index];
    editIndexInput.value = index.toString();
    entryNameInput.value = entry.name;
    entryUrlInput.value = entry.url;
    entryUsernameInput.value = entry.username;
    entryPasswordInput.value = entry.password;
    entryNoteInput.value = entry.note;
    modalTitle.textContent = 'Edit Credentials';
  } else {
    entryForm.reset();
    editIndexInput.value = '';
    modalTitle.textContent = 'Add New Entry';
  }
  entryModal.classList.remove('hidden');
}

function closeEntryModal() { entryModal.classList.add('hidden'); }

async function handleFormSubmit(e: Event) {
  e.preventDefault();
  const entry = {
    name: entryNameInput.value,
    url: entryUrlInput.value,
    username: entryUsernameInput.value,
    password: entryPasswordInput.value,
    note: entryNoteInput.value
  };
  const index = editIndexInput.value;
  let res;
  if (index) {
    res = await sendMessage('UPDATE_ENTRY', { index: parseInt(index), newPassword: entry.password });
    // Note: full entry update logic should be refined in SW
  } else {
    res = await sendMessage('ADD_ENTRY', { entry });
  }

  if (res.success) {
    closeEntryModal();
    await loadEntries();
  }
}

function handleSearch() {
  const q = globalSearch.value.toLowerCase();
  const filtered = allEntries.filter(e => 
    e.name.toLowerCase().includes(q) || 
    e.url.toLowerCase().includes(q) || 
    e.username.toLowerCase().includes(q)
  );
  renderEntries(filtered);
}

async function handleSetupRecoveryKey() {
  const res = await sendMessage('GENERATE_RECOVERY_KEY');
  if (res.recoveryKey) {
    alert(`SAVE THIS KEY EXTERNALLY:\n\n${res.recoveryKey}`);
  }
}

async function handleExport() {
  const res = await sendMessage('EXPORT_CSV');
  if (res.csvContent) {
    const blob = new Blob([res.csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `eigenvault-export-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  }
}

async function handleImport(e: any) {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  const res = await sendMessage('IMPORT_CSV', { csvContent: text });
  alert(`Imported ${res.imported} new records.`);
  await loadEntries();
}

async function handleResetVault() {
  if (confirm('CRITICAL: Delete ALL vault data permanently?')) {
    await chrome.storage.local.clear();
    location.reload();
  }
}

function lockVault() {
  sendMessage('LOCK_VAULT').then(() => location.reload());
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Global window functions for table actions
(window as any).copyEntry = async (i: number) => {
  await navigator.clipboard.writeText(allEntries[i].password);
};
(window as any).editEntry = (i: number) => openEntryModal(i);
(window as any).deleteEntry = async (i: number) => {
  if (confirm('Delete this record?')) {
    const res = await sendMessage('DELETE_ENTRY', { index: i });
    if (res.success) await loadEntries();
  }
};

init();
