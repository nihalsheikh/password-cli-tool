/**
 * Dashboard UI Controller for EigenVault - Redesigned
 */
import { generatePassword } from '../core/password-gen.js';
// State
let allEntries = [];
// DOM Elements - Navigation
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const themeToggle = document.getElementById('theme-toggle');
// All Passwords View
const passwordTbody = document.getElementById('password-tbody');
const passwordCount = document.getElementById('password-count');
const globalSearch = document.getElementById('global-search');
const addNewBtn = document.getElementById('add-new-btn');
// Generator View
const genPasswordEl = document.getElementById('gen-password');
const genCopyBtn = document.getElementById('gen-copy');
const genSaveBtn = document.getElementById('gen-save');
const genRegenerateBtn = document.getElementById('gen-regenerate');
const genLengthSlider = document.getElementById('gen-length');
const lengthValue = document.getElementById('length-value');
const optUppercase = document.getElementById('opt-uppercase');
const optLowercase = document.getElementById('opt-lowercase');
const optDigits = document.getElementById('opt-digits');
const optSpecial = document.getElementById('opt-special');
// Settings View
const autolockTimeout = document.getElementById('autolock-timeout');
const setupBiometricBtn = document.getElementById('setup-biometric');
const exportBtnSettings = document.getElementById('export-btn-settings');
const settingsImportInput = document.getElementById('settings-import');
const resetVaultBtn = document.getElementById('reset-vault');
const setupRecoveryKeyBtn = document.getElementById('setup-recovery-key');
const setupTotpBtn = document.getElementById('setup-totp');
const setupOtpBtn = document.getElementById('setup-otp');
const lockVaultBtn = document.getElementById('lock-vault-btn');
// Entry Modal
const entryModal = document.getElementById('entry-modal');
const modalTitle = document.getElementById('modal-title');
const modalClose = document.getElementById('modal-close');
const modalCancel = document.getElementById('modal-cancel');
const entryForm = document.getElementById('entry-form');
const editIndexInput = document.getElementById('edit-index');
const entryNameInput = document.getElementById('entry-name');
const entryUrlInput = document.getElementById('entry-url');
const entryUsernameInput = document.getElementById('entry-username');
const entryPasswordInput = document.getElementById('entry-password');
const entryNoteInput = document.getElementById('entry-note');
const togglePasswordBtn = document.getElementById('toggle-password');
const generatePasswordBtn = document.getElementById('generate-password');
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
            const targetView = item.dataset.view;
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
    genSaveBtn.addEventListener('click', () => {
        const pass = genPasswordEl.textContent;
        openEntryModal();
        if (pass && pass !== '••••••••••••••••') {
            entryPasswordInput.value = pass;
            entryPasswordInput.type = 'text';
        }
    });
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
function renderEntries(entries) {
    passwordCount.textContent = entries.length.toString();
    if (entries.length === 0) {
        passwordTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 48px; color: var(--text-muted);">No records found in vault.</td></tr>';
        return;
    }
    passwordTbody.innerHTML = entries.map((entry, index) => `
    <tr>
      <td>
        <div class="site-cell">
          <div class="site-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.8 17 5 19 5a1 1 0 0 1 1 1z"/></svg>
          </div>
          <div>
            <div class="site-name">${escapeHtml(entry.name || 'Account')}</div>
            <div class="site-url">${escapeHtml(entry.url)}</div>
          </div>
        </div>
      </td>
      <td class="mono-cell">${escapeHtml(entry.username)}</td>
      <td class="mono-cell">${escapeHtml(entry.url)}</td>
      <td><span class="success-text" style="font-size: 10px; font-weight: 700;">ENCRYPTED</span></td>
      <td style="text-align: right; display: flex; gap: 4px; justify-content: flex-end;">
        <button class="icon-btn" title="Copy" onclick="window.copyEntry(${index})">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
        </button>
        <button class="icon-btn" title="Edit" onclick="window.editEntry(${index})">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-pencil"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>
        </button>
        <button class="icon-btn" title="Delete" onclick="window.deleteEntry(${index})">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-trash-2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/></svg>
        </button>
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
function openEntryModal(index) {
    if (index !== undefined) {
        const entry = allEntries[index];
        editIndexInput.value = index.toString();
        entryNameInput.value = entry.name;
        entryUrlInput.value = entry.url;
        entryUsernameInput.value = entry.username;
        entryPasswordInput.value = entry.password;
        entryNoteInput.value = entry.note;
        modalTitle.textContent = 'Edit Credentials';
    }
    else {
        entryForm.reset();
        editIndexInput.value = '';
        modalTitle.textContent = 'Add New Entry';
    }
    entryModal.classList.remove('hidden');
}
function closeEntryModal() { entryModal.classList.add('hidden'); }
async function handleFormSubmit(e) {
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
        res = await sendMessage('UPDATE_ENTRY', { index: parseInt(index), entry });
    }
    else {
        res = await sendMessage('ADD_ENTRY', { entry });
    }
    if (res.success) {
        closeEntryModal();
        await loadEntries();
    }
}
function handleSearch() {
    const q = globalSearch.value.toLowerCase();
    const filtered = allEntries.filter(e => e.name.toLowerCase().includes(q) ||
        e.url.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q));
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
        a.download = `eigenvault-export-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
    }
}
async function handleImport(e) {
    const file = e.target.files[0];
    if (!file)
        return;
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
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
// Global window functions for table actions
window.copyEntry = async (i) => {
    await navigator.clipboard.writeText(allEntries[i].password);
};
window.editEntry = (i) => openEntryModal(i);
window.deleteEntry = async (i) => {
    if (confirm('Delete this record?')) {
        const res = await sendMessage('DELETE_ENTRY', { index: i });
        if (res.success)
            await loadEntries();
    }
};
init();
//# sourceMappingURL=dashboard.js.map