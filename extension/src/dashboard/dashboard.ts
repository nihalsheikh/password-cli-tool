/**
 * Dashboard UI Controller for EigenVault
 */

import { generatePassword, isPasswordStrong, getPasswordStrengthScore } from '../core/password-gen';

// State
let allEntries: Array<{ name: string; url: string; username: string; password: string; note: string }> = [];
let deleteTargetIndex: number = -1;

// DOM Elements
const globalSearch = document.getElementById('global-search') as HTMLInputElement;
const addNewBtn = document.getElementById('add-new-btn') as HTMLButtonElement;
const exportBtn = document.getElementById('export-btn') as HTMLButtonElement;
const importBtn = document.getElementById('import-btn') as HTMLButtonElement;
const lockVaultBtn = document.getElementById('lock-vault-btn') as HTMLButtonElement;
const passwordTbody = document.getElementById('password-tbody') as HTMLTableSectionElement;
const passwordCount = document.getElementById('password-count') as HTMLElement;
const entryModal = document.getElementById('entry-modal') as HTMLElement;
const deleteModal = document.getElementById('delete-modal') as HTMLElement;
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
const deleteModalClose = document.getElementById('delete-modal-close') as HTMLButtonElement;
const deleteCancel = document.getElementById('delete-cancel') as HTMLButtonElement;
const deleteConfirm = document.getElementById('delete-confirm') as HTMLButtonElement;
const deleteTarget = document.getElementById('delete-target') as HTMLElement;

// Generator elements
const genPasswordEl = document.getElementById('gen-password') as HTMLElement;
const genCopyBtn = document.getElementById('gen-copy') as HTMLButtonElement;
const genRegenerateBtn = document.getElementById('gen-regenerate') as HTMLButtonElement;
const genLengthSlider = document.getElementById('gen-length') as HTMLInputElement;
const lengthValue = document.getElementById('length-value') as HTMLElement;
const optUppercase = document.getElementById('opt-uppercase') as HTMLInputElement;
const optLowercase = document.getElementById('opt-lowercase') as HTMLInputElement;
const optDigits = document.getElementById('opt-digits') as HTMLInputElement;
const optSpecial = document.getElementById('opt-special') as HTMLInputElement;

// Settings elements
const autolockTimeout = document.getElementById('autolock-timeout') as HTMLSelectElement;
const setupBiometricBtn = document.getElementById('setup-biometric') as HTMLButtonElement;
const settingsExportBtn = document.getElementById('settings-export') as HTMLButtonElement;
const settingsImportInput = document.getElementById('settings-import') as HTMLInputElement;
const resetVaultBtn = document.getElementById('reset-vault') as HTMLButtonElement;

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
 * Initialize dashboard
 */
async function init() {
  setupNavigation();
  setupEventListeners();
  await loadEntries();
  generateInitialPassword();
}

/**
 * Setup navigation
 */
function setupNavigation() {
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
      item.classList.add('active');

      const view = (item as HTMLElement).dataset.view;
      document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
      document.getElementById(`view-${view}`)?.classList.add('active');
    });
  });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Header actions
  globalSearch.addEventListener('input', handleSearch);
  addNewBtn.addEventListener('click', () => openEntryModal());
  exportBtn.addEventListener('click', handleExport);
  importBtn.addEventListener('click', () => document.getElementById('settings-import')?.click());
  lockVaultBtn.addEventListener('click', lockVault);

  // Modal
  modalClose.addEventListener('click', closeEntryModal);
  modalCancel.addEventListener('click', closeEntryModal);
  entryForm.addEventListener('submit', handleFormSubmit);
  togglePasswordBtn.addEventListener('click', togglePasswordVisibility);
  generatePasswordBtn.addEventListener('click', generateInlinePassword);

  // Delete modal
  deleteModalClose.addEventListener('click', closeDeleteModal);
  deleteCancel.addEventListener('click', closeDeleteModal);
  deleteConfirm.addEventListener('click', confirmDelete);

  // Generator
  genCopyBtn.addEventListener('click', copyGeneratedPassword);
  genRegenerateBtn.addEventListener('click', generatePasswordDisplay);
  genLengthSlider.addEventListener('input', (e) => {
    lengthValue.textContent = (e.target as HTMLInputElement).value;
    generatePasswordDisplay();
  });
  [optUppercase, optLowercase, optDigits, optSpecial].forEach((cb) => {
    cb.addEventListener('change', generatePasswordDisplay);
  });

  // Settings
  autolockTimeout.addEventListener('change', handleAutolockChange);
  setupBiometricBtn.addEventListener('click', setupBiometric);
  settingsExportBtn.addEventListener('click', handleExport);
  settingsImportInput.addEventListener('change', handleImport);
  resetVaultBtn.addEventListener('click', handleResetVault);
}

/**
 * Load all password entries
 */
async function loadEntries() {
  const response = await sendMessage('GET_ENTRIES') as { entries?: typeof allEntries; error?: string };

  if (response.error) {
    window.location.href = 'popup/popup.html';
    return;
  }

  allEntries = response.entries || [];
  renderEntries(allEntries);
}

/**
 * Render entries to table
 */
function renderEntries(entries: typeof allEntries) {
  passwordCount.textContent = entries.length.toString();

  if (entries.length === 0) {
    passwordTbody.innerHTML = `
      <tr>
        <td colspan="5">
          <div class="empty-state">
            <div class="empty-state-icon">📭</div>
            <h3>No passwords stored</h3>
            <p>Click "Add New" to create your first password entry</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  passwordTbody.innerHTML = entries.map((entry, index) => `
    <tr>
      <td>
        <div class="table-site">
          <div class="site-icon">🔐</div>
          <div class="site-info">
            <div class="site-name">${escapeHtml(entry.name || getDomain(entry.url))}</div>
            <div class="site-url">${escapeHtml(entry.url)}</div>
          </div>
        </div>
      </td>
      <td class="cell-username">${escapeHtml(entry.username)}</td>
      <td class="cell-username">${escapeHtml(entry.url)}</td>
      <td class="cell-notes">${escapeHtml(entry.note || '—')}</td>
      <td class="cell-actions">
        <button class="action-icon-btn" title="Copy Password" data-action="copy" data-index="${index}">📋</button>
        <button class="action-icon-btn" title="Edit" data-action="edit" data-index="${index}">✏️</button>
        <button class="action-icon-btn" title="Delete" data-action="delete" data-index="${index}">🗑️</button>
      </td>
    </tr>
  `).join('');

  // Add event listeners
  passwordTbody.querySelectorAll('[data-action]').forEach((btn) => {
    btn.addEventListener('click', handleTableAction);
  });
}

/**
 * Handle table action buttons
 */
function handleTableAction(e: Event) {
  const target = e.target as HTMLButtonElement;
  const action = target.dataset.action;
  const index = parseInt(target.dataset.index || '0', 10);

  switch (action) {
    case 'copy':
      copyPassword(index);
      break;
    case 'edit':
      openEntryModal(index);
      break;
    case 'delete':
      openDeleteModal(index);
      break;
  }
}

/**
 * Copy password to clipboard
 */
async function copyPassword(index: number) {
  const entry = allEntries[index];
  try {
    await navigator.clipboard.writeText(entry.password);
    // Show brief feedback
    const btn = passwordTbody.querySelector(`[data-action="copy"][data-index="${index}"]`) as HTMLButtonElement;
    btn.textContent = '✓';
    setTimeout(() => { btn.textContent = '📋'; }, 1500);
  } catch {
    alert('Failed to copy to clipboard');
  }
}

/**
 * Handle search
 */
function handleSearch() {
  const query = globalSearch.value.toLowerCase();

  if (!query) {
    renderEntries(allEntries);
    return;
  }

  const filtered = allEntries.filter((entry) =>
    entry.name.toLowerCase().includes(query) ||
    entry.url.toLowerCase().includes(query) ||
    entry.username.toLowerCase().includes(query) ||
    entry.note.toLowerCase().includes(query)
  );

  renderEntries(filtered);
}

/**
 * Open entry modal
 */
function openEntryModal(index?: number) {
  if (index !== undefined && allEntries[index]) {
    const entry = allEntries[index];
    editIndexInput.value = index.toString();
    entryNameInput.value = entry.name;
    entryUrlInput.value = entry.url;
    entryUsernameInput.value = entry.username;
    entryPasswordInput.value = entry.password;
    entryNoteInput.value = entry.note;
    document.getElementById('modal-title')!.textContent = 'Edit Password';
  } else {
    editIndexInput.value = '';
    entryForm.reset();
    document.getElementById('modal-title')!.textContent = 'Add Password';
  }

  entryModal.classList.remove('hidden');
}

/**
 * Close entry modal
 */
function closeEntryModal() {
  entryModal.classList.add('hidden');
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility() {
  const type = entryPasswordInput.type === 'password' ? 'text' : 'password';
  entryPasswordInput.type = type;
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

  const editIndex = editIndexInput.value ? parseInt(editIndexInput.value, 10) : -1;
  const entry = {
    name: entryNameInput.value || getDomain(entryUrlInput.value),
    url: entryUrlInput.value,
    username: entryUsernameInput.value,
    password: entryPasswordInput.value,
    note: entryNoteInput.value,
  };

  if (editIndex >= 0) {
    // Update existing
    const response = await sendMessage('UPDATE_ENTRY', { index: editIndex, newPassword: entry.password }) as { success: boolean; error?: string };
    if (response.success) {
      // Also update other fields
      allEntries[editIndex] = entry;
      // Re-save all entries with updated data
      await sendMessage('SAVE_ALL_ENTRIES', { entries: allEntries });
    }
  } else {
    // Add new
    const response = await sendMessage('ADD_ENTRY', { entry }) as { success: boolean; error?: string };
    if (response.success) {
      allEntries.push(entry);
    }
  }

  closeEntryModal();
  renderEntries(allEntries);
}

/**
 * Open delete modal
 */
function openDeleteModal(index: number) {
  deleteTargetIndex = index;
  const entry = allEntries[index];
  deleteTarget.textContent = `${entry.username} at ${entry.url}`;
  deleteModal.classList.remove('hidden');
}

/**
 * Close delete modal
 */
function closeDeleteModal() {
  deleteModal.classList.add('hidden');
  deleteTargetIndex = -1;
}

/**
 * Confirm delete
 */
async function confirmDelete() {
  if (deleteTargetIndex < 0) return;

  const response = await sendMessage('DELETE_ENTRY', { index: deleteTargetIndex }) as { success: boolean; error?: string };
  if (response.success) {
    allEntries.splice(deleteTargetIndex, 1);
    renderEntries(allEntries);
  }

  closeDeleteModal();
}

/**
 * Handle export
 */
async function handleExport() {
  const response = await sendMessage('EXPORT_CSV') as { csvContent?: string; error?: string };

  if (response.error || !response.csvContent) {
    alert('Failed to export');
    return;
  }

  // Download as file
  const blob = new Blob([response.csvContent], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `eigenvault-export-${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Handle import
 */
async function handleImport(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;

  const text = await file.text();
  const response = await sendMessage('IMPORT_CSV', { csvContent: text }) as { imported?: number; updated?: number; error?: string };

  if (response.error) {
    alert('Failed to import: ' + response.error);
    return;
  }

  alert(`Imported ${response.imported} new passwords, updated ${response.updated} existing`);
  await loadEntries();
}

/**
 * Handle autolock change
 */
async function handleAutolockChange() {
  const minutes = parseInt(autolockTimeout.value, 10);
  await sendMessage('SET_AUTO_LOCK', { minutes });
}

/**
 * Setup biometric
 */
async function setupBiometric() {
  alert('Biometric setup would be implemented here using WebAuthn API');
}

/**
 * Handle reset vault
 */
async function handleResetVault() {
  if (confirm('Are you sure? This will delete ALL passwords permanently!')) {
    // This would need a new message type in service worker
    alert('Vault reset would be implemented here');
  }
}

/**
 * Lock vault
 */
async function lockVault() {
  await sendMessage('LOCK_VAULT');
  window.location.href = 'popup/popup.html';
}

/**
 * Generate initial password for generator view
 */
function generateInitialPassword() {
  generatePasswordDisplay();
}

/**
 * Generate password and display
 */
function generatePasswordDisplay() {
  const options = {
    length: parseInt(genLengthSlider.value, 10),
    useUppercase: optUppercase.checked,
    useLowercase: optLowercase.checked,
    useDigits: optDigits.checked,
    useSpecial: optSpecial.checked,
  };

  const password = generatePassword(options);
  const strength = getPasswordStrengthScore(password);

  genPasswordEl.textContent = password;

  const strengthBar = document.querySelector('.strength-meter-large .strength-bar') as HTMLElement;
  const strengthText = document.getElementById('gen-strength')!;

  const colors = ['var(--danger)', 'var(--warning)', '#84cc16', 'var(--success)', 'var(--primary)'];
  const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

  strengthBar.style.setProperty('--strength-width', `${(strength.score / 5) * 100}%`);
  strengthBar.style.background = colors[strength.score];
  strengthText.textContent = labels[strength.score];
  strengthText.style.color = colors[strength.score];
}

/**
 * Copy generated password
 */
async function copyGeneratedPassword() {
  const password = genPasswordEl.textContent || '';
  try {
    await navigator.clipboard.writeText(password);
    genCopyBtn.textContent = '✓';
    setTimeout(() => { genCopyBtn.textContent = '📋'; }, 1500);
  } catch {
    alert('Failed to copy');
  }
}

/**
 * Get domain from URL
 */
function getDomain(url: string): string {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    return url;
  }
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
