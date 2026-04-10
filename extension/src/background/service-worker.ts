/**
 * Background Service Worker for EigenVault Extension
 * Handles secure key management, message routing, and coordination
 */

import {
  isVaultInitialized,
  initializeVault,
  unlockVault,
  lockVault,
  isVaultUnlocked,
  readPasswordEntries,
  writePasswordEntries,
  addPasswordEntry,
  updatePasswordEntry,
  deletePasswordEntry,
  searchPasswordEntries,
  exportToCSV,
  importFromCSV,
  type PasswordEntry,
} from '../core/storage';

import { isWebAuthnSupported, authenticateWithBiometric } from '../core/webauthn';
import { generatePassword, isPasswordStrong, isValidUrl, getNameFromUrl } from '../core/password-gen';

// In-memory key cache (cleared on lock/logout)
let dataEncryptionKey: CryptoKey | null = null;
let unlockTimestamp: number | null = null;

// Auto-lock timeout (default 15 minutes)
let autoLockMinutes = 15;

/**
 * Check if session has expired due to auto-lock
 */
function isSessionExpired(): boolean {
  if (!unlockTimestamp) return true;
  const elapsed = (Date.now() - unlockTimestamp) / 1000 / 60; // minutes
  return elapsed >= autoLockMinutes;
}

/**
 * Get current key, checking session validity
 */
async function getValidKey(): Promise<CryptoKey | null> {
  if (!dataEncryptionKey) return null;
  if (isSessionExpired()) {
    await lockVault();
    dataEncryptionKey = null;
    return null;
  }
  return dataEncryptionKey;
}

/**
 * Reset auto-lock timer
 */
function resetAutoLockTimer() {
  unlockTimestamp = Date.now();
}

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.type) {
        case 'CHECK_INITIALIZED':
          sendResponse({ initialized: await isVaultInitialized() });
          break;

        case 'INITIALIZE_VAULT':
          {
            const success = await initializeVault(message.masterPassword);
            sendResponse({ success });
          }
          break;

        case 'UNLOCK_WITH_PASSWORD':
          {
            const result = await unlockVault(message.masterPassword);
            if (result.success && result.key) {
              dataEncryptionKey = result.key;
              unlockTimestamp = Date.now();
              // Load auto-lock setting
              const pref = await chrome.storage.sync.get(['eigen_autolock_minutes']);
              autoLockMinutes = pref['eigen_autolock_minutes'] || 15;
            }
            sendResponse(result);
          }
          break;

        case 'UNLOCK_WITH_BIOMETRIC':
          {
            const key = await getValidKey();
            if (key) {
              // Already unlocked
              sendResponse({ success: true });
            } else {
              // Need to authenticate - but we need master password first time
              // Biometric is for quick unlock after initial password unlock
              sendResponse({ success: false, error: 'Password required first' });
            }
          }
          break;

        case 'LOCK_VAULT':
          {
            await lockVault();
            dataEncryptionKey = null;
            unlockTimestamp = null;
            sendResponse({ success: true });
          }
          break;

        case 'CHECK_UNLOCKED':
          {
            const key = await getValidKey();
            sendResponse({ unlocked: key !== null, expired: isSessionExpired() });
          }
          break;

        case 'GET_ENTRIES':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const entries = await readPasswordEntries(key);
            sendResponse({ entries });
          }
          break;

        case 'ADD_ENTRY':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const success = await addPasswordEntry(message.entry as PasswordEntry, key);
            sendResponse({ success });
          }
          break;

        case 'UPDATE_ENTRY':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const success = await updatePasswordEntry(
              message.index,
              message.newPassword,
              key
            );
            sendResponse({ success });
          }
          break;

        case 'DELETE_ENTRY':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const success = await deletePasswordEntry(message.index, key);
            sendResponse({ success });
          }
          break;

        case 'SEARCH_ENTRIES':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const entries = await searchPasswordEntries(message.query, key);
            sendResponse({ entries });
          }
          break;

        case 'GENERATE_PASSWORD':
          {
            const password = generatePassword(message.options);
            const strong = isPasswordStrong(password);
            sendResponse({ password, strong });
          }
          break;

        case 'EXPORT_CSV':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const csvContent = await exportToCSV(key);
            sendResponse({ csvContent });
          }
          break;

        case 'IMPORT_CSV':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();
            const result = await importFromCSV(message.csvContent, key);
            sendResponse(result);
          }
          break;

        case 'SET_AUTO_LOCK':
          {
            autoLockMinutes = message.minutes;
            await chrome.storage.sync.set({ eigen_autolock_minutes: message.minutes });
            sendResponse({ success: true });
          }
          break;

        case 'CHECK_WEBAUTHN':
          {
            const supported = isWebAuthnSupported();
            sendResponse({ supported });
          }
          break;

        case 'GET_MATCHING_ENTRIES':
          {
            // Get entries matching current tab URL for auto-fill
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            resetAutoLockTimer();

            const allEntries = await readPasswordEntries(key);
            const tab = await chrome.tabs.query({ active: true, currentWindow: true });
            const currentUrl = tab[0]?.url || '';

            // Extract domain from URL
            let domain = '';
            try {
              const urlObj = new URL(currentUrl);
              domain = urlObj.hostname;
            } catch {
              // Invalid URL
            }

            // Find matching entries
            const matches = allEntries.filter(entry => {
              try {
                const entryDomain = new URL(entry.url).hostname;
                return entryDomain === domain || entryDomain.endsWith('.' + domain) || domain.endsWith('.' + entryDomain);
              } catch {
                return false;
              }
            });

            sendResponse({ matches, domain });
          }
          break;

        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Service worker error:', error);
      sendResponse({ error: error instanceof Error ? error.message : 'Unknown error' });
    }
  })();

  return true; // Keep channel open for async response
});

// Context menu setup
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'eigenvault_generate',
    title: 'Generate Password with EigenVault',
    contexts: ['editable'],
  });

  chrome.contextMenus.create({
    id: 'eigenvault_autofill',
    title: 'Auto-fill with EigenVault',
    contexts: ['editable'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'eigenvault_generate') {
    const password = generatePassword({ length: 16 });
    await chrome.tabs.sendMessage(tab!.id!, { type: 'FILL_PASSWORD', password });
  } else if (info.menuItemId === 'eigenvault_autofill') {
    await chrome.tabs.sendMessage(tab!.id!, { type: 'TRIGGER_AUTOFILL' });
  }
});

// Keyboard shortcut handler
chrome.commands.onCommand.addListener(async (command) => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  switch (command) {
    case 'autofill':
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, { type: 'TRIGGER_AUTOFILL' });
      }
      break;
    case 'generate':
      // Open popup for password generation
      chrome.action.openPopup();
      break;
  }
});

// Clean up on service worker restart
self.addEventListener('activate', () => {
  // Key stays in memory, but session may need re-validation
});
