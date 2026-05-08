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
  generateRecoveryKey,
  resetMasterPassword,
  readMFASettings,
  updateMFASettings,
  type PasswordEntry,
} from '../core/storage.js';

import { isWebAuthnSupported, authenticateWithBiometric } from '../core/webauthn.js';
import { generatePassword, isPasswordStrong, isValidUrl, getNameFromUrl } from '../core/password-gen.js';
import { generateSecret, verifyTOTP } from '../core/otp.js';

// State
let dataEncryptionKey: CryptoKey | null = null;
let pendingKey: CryptoKey | null = null; // Key that passed password check but needs MFA
let unlockTimestamp: number | null = null;
let nativePort: chrome.runtime.Port | null = null;

// Connect to Native Messaging Host
function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative('com.eigenvault.sync');
    nativePort.onMessage.addListener((msg) => {
      console.log('[EigenVault] Native message received:', msg);
    });
    nativePort.onDisconnect.addListener(() => {
      console.log('[EigenVault] Native host disconnected:', chrome.runtime.lastError);
      nativePort = null;
    });
  } catch (err) {
    console.log('[EigenVault] Native messaging not available');
  }
}

connectNative();

// Auto-lock timeout (default 5 minutes)
let autoLockMinutes = 5;

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
      console.log(`[EigenVault] Processing message: ${message.type}`);
      switch (message.type) {
        case 'CHECK_INITIALIZED':
          const initialized = await isVaultInitialized();
          sendResponse({ initialized });
          break;

        case 'INITIALIZE_VAULT':
          {
            try {
              const success = await initializeVault(message.masterPassword);
              sendResponse({ success });
            } catch (initError) {
              console.error('[EigenVault] Initialization failed:', initError);
              sendResponse({ success: false, error: `Init failed: ${initError instanceof Error ? initError.message : 'Unknown'}` });
            }
          }
          break;

        case 'UNLOCK_WITH_PASSWORD':
          {
            try {
              const result = await unlockVault(message.masterPassword);
              if (result.success && result.key) {
                // Check if MFA is enabled
                const mfa = await readMFASettings(result.key);
                if (mfa.totpEnabled) {
                  pendingKey = result.key;
                  sendResponse({ success: true, mfaRequired: true });
                  return;
                }

                dataEncryptionKey = result.key;
                unlockTimestamp = Date.now();
                const pref = await chrome.storage.local.get(['eigen_autolock_minutes']);
                autoLockMinutes = pref['eigen_autolock_minutes'] || 15;
              }
              sendResponse(result);
            } catch (unlockError) {
              console.error('[EigenVault] Unlock failed:', unlockError);
              sendResponse({ success: false, error: `Unlock failed: ${unlockError instanceof Error ? unlockError.message : 'Unknown'}` });
            }
          }
          break;

        case 'VERIFY_MFA_CODE':
          {
            if (!pendingKey) {
              sendResponse({ success: false, error: 'No pending session' });
              return;
            }
            const mfa = await readMFASettings(pendingKey);
            if (mfa.totpSecret) {
              const valid = await verifyTOTP(mfa.totpSecret, message.code);
              if (valid) {
                dataEncryptionKey = pendingKey;
                pendingKey = null;
                unlockTimestamp = Date.now();
                sendResponse({ success: true });
              } else {
                sendResponse({ success: false, error: 'Invalid MFA code' });
              }
            } else {
              sendResponse({ success: false, error: 'MFA not configured' });
            }
          }
          break;

        case 'VERIFY_MFA_CODE_MOCK':
          {
            const valid = await verifyTOTP(message.secret, message.code);
            sendResponse({ success: valid });
          }
          break;

        case 'GET_MFA_SETTINGS':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            const mfa = await readMFASettings(key);
            sendResponse({ mfa });
          }
          break;

        case 'GENERATE_TOTP_SECRET':
          {
            const secret = generateSecret();
            sendResponse({ secret });
          }
          break;

        case 'UPDATE_MFA_SETTINGS':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            const success = await updateMFASettings(message.settings, key);
            sendResponse({ success });
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
              message.entry as PasswordEntry,
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
            await chrome.storage.local.set({ eigen_autolock_minutes: message.minutes });
            sendResponse({ success: true });
          }
          break;

        case 'CHECK_WEBAUTHN':
          {
            const supported = isWebAuthnSupported();
            sendResponse({ supported });
          }
          break;

        case 'GET_BROWSER_PASSWORDS':
          {
            // Note: Direct browser credential access requires high-privilege APIs 
            // often restricted to system apps. As a safe fallback for modern browsers,
            // we provide instructions or trigger the built-in export/import bridge.
            sendResponse({ error: 'Direct browser access requires user confirmation via CSV export for security.' });
          }
          break;

        case 'GENERATE_RECOVERY_KEY':
          {
            const key = await getValidKey();
            if (!key) {
              sendResponse({ error: 'Vault locked' });
              return;
            }
            const recoveryKey = await generateRecoveryKey(key);
            sendResponse({ recoveryKey });
          }
          break;

        case 'RESET_MASTER_PASSWORD':
          {
            const success = await resetMasterPassword(message.recoveryKey, message.newPassword);
            sendResponse({ success });
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
