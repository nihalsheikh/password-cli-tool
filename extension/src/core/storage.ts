/**
 * Encrypted storage layer using chrome.storage.sync
 * All data is encrypted before storage using AES-GCM
 */

import {
  deriveKey,
  encrypt,
  decrypt,
  generateSalt,
  exportKey,
  importKey,
  hashData,
  getRandomBytes,
} from './crypto';

// Storage keys
const STORAGE_KEYS = {
  MASTER_HASH: 'eigen_master_hash',
  ENCRYPTED_KEY: 'eigen_encrypted_key',
  SALT: 'eigen_salt',
  ENCRYPTED_DATA: 'eigen_encrypted_data',
  WEBAUTHN_CREDENTIAL: 'eigen_webauthn_cred',
  SESSION_UNLOCKED: 'eigen_session_unlocked',
  AUTO_LOCK_MINUTES: 'eigen_autolock_minutes',
} as const;

// Password entry type matching CSV format
export interface PasswordEntry {
  name: string;
  url: string;
  username: string;
  password: string;
  note: string;
}

// Encrypted data structure
interface EncryptedData {
  entries: PasswordEntry[];
  lastModified: number;
}

/**
 * Check if vault is initialized (master password set)
 */
export async function isVaultInitialized(): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.storage.sync.get([STORAGE_KEYS.SALT], (result) => {
      resolve(!!result[STORAGE_KEYS.SALT]);
    });
  });
}

/**
 * Initialize vault with master password
 */
export async function initializeVault(masterPassword: string): Promise<boolean> {
  const salt = generateSalt();
  const key = await deriveKey(masterPassword, salt);
  const masterHash = await hashData(masterPassword);

  // Generate and encrypt the data encryption key
  const dataKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const exportedDataKey = await exportKey(dataKey);
  const { ciphertext: encryptedKey, iv: keyIv } = await encrypt(
    JSON.stringify({ key: Array.from(exportedDataKey) }),
    key
  );

  // Store initialization data
  await chrome.storage.sync.set({
    [STORAGE_KEYS.SALT]: Array.from(salt),
    [STORAGE_KEYS.ENCRYPTED_KEY]: {
      ciphertext: Array.from(encryptedKey),
      iv: Array.from(keyIv),
    },
    [STORAGE_KEYS.MASTER_HASH]: Array.from(masterHash),
    [STORAGE_KEYS.ENCRYPTED_DATA]: {
      ciphertext: [],
      iv: [],
    },
  });

  return true;
}

/**
 * Unlock vault with master password
 * Returns the data encryption key if successful
 */
export async function unlockVault(
  masterPassword: string
): Promise<{ success: boolean; key?: CryptoKey; error?: string }> {
  try {
    const result = await chrome.storage.sync.get([
      STORAGE_KEYS.SALT,
      STORAGE_KEYS.ENCRYPTED_KEY,
      STORAGE_KEYS.MASTER_HASH,
    ]);

    const salt = new Uint8Array(result[STORAGE_KEYS.SALT]);
    const encryptedKey = result[STORAGE_KEYS.ENCRYPTED_KEY];
    const storedHash = new Uint8Array(result[STORAGE_KEYS.MASTER_HASH]);

    // Verify password
    const passwordHash = await hashData(masterPassword);
    if (!storedHash.every((byte, i) => byte === passwordHash[i])) {
      return { success: false, error: 'Invalid master password' };
    }

    // Derive key and decrypt data key
    const key = await deriveKey(masterPassword, salt);
    const keyData = await decrypt(
      new Uint8Array(encryptedKey.ciphertext),
      new Uint8Array(encryptedKey.iv),
      key
    );

    const parsed = JSON.parse(keyData);
    const dataKey = await importKey(new Uint8Array(parsed.key));

    // Mark session as unlocked
    await chrome.storage.sync.set({
      [STORAGE_KEYS.SESSION_UNLOCKED]: true,
    });

    return { success: true, key: dataKey };
  } catch (error) {
    return { success: false, error: 'Failed to unlock vault' };
  }
}

/**
 * Lock the vault (clears session)
 */
export async function lockVault(): Promise<void> {
  await chrome.storage.sync.set({
    [STORAGE_KEYS.SESSION_UNLOCKED]: false,
  });
}

/**
 * Check if vault is currently unlocked
 */
export async function isVaultUnlocked(): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.storage.sync.get([STORAGE_KEYS.SESSION_UNLOCKED], (result) => {
      resolve(result[STORAGE_KEYS.SESSION_UNLOCKED] === true);
    });
  });
}

/**
 * Get decrypted data encryption key if unlocked
 */
export async function getDataKey(): Promise<CryptoKey | null> {
  const result = await chrome.storage.sync.get([
    STORAGE_KEYS.SALT,
    STORAGE_KEYS.ENCRYPTED_KEY,
    STORAGE_KEYS.SESSION_UNLOCKED,
  ]);

  if (!result[STORAGE_KEYS.SESSION_UNLOCKED]) {
    return null;
  }

  try {
    // Key is cached in memory by background script after unlock
    // This is a simplified version - full implementation would cache the key
    return null;
  } catch {
    return null;
  }
}

/**
 * Read and decrypt password entries
 */
export async function readPasswordEntries(
  dataKey: CryptoKey
): Promise<PasswordEntry[]> {
  const result = await chrome.storage.sync.get([STORAGE_KEYS.ENCRYPTED_DATA]);
  const encryptedData = result[STORAGE_KEYS.ENCRYPTED_DATA];

  if (!encryptedData?.ciphertext?.length) {
    return [];
  }

  try {
    const decrypted = await decrypt(
      new Uint8Array(encryptedData.ciphertext),
      new Uint8Array(encryptedData.iv),
      dataKey
    );

    const data: EncryptedData = JSON.parse(decrypted);
    return data.entries || [];
  } catch {
    return [];
  }
}

/**
 * Write and encrypt password entries
 */
export async function writePasswordEntries(
  entries: PasswordEntry[],
  dataKey: CryptoKey
): Promise<boolean> {
  try {
    const data: EncryptedData = {
      entries,
      lastModified: Date.now(),
    };

    const { ciphertext, iv } = await encrypt(JSON.stringify(data), dataKey);

    await chrome.storage.sync.set({
      [STORAGE_KEYS.ENCRYPTED_DATA]: {
        ciphertext: Array.from(ciphertext),
        iv: Array.from(iv),
      },
    });

    return true;
  } catch {
    return false;
  }
}

/**
 * Add a new password entry
 */
export async function addPasswordEntry(
  entry: PasswordEntry,
  dataKey: CryptoKey
): Promise<boolean> {
  const entries = await readPasswordEntries(dataKey);
  entries.push(entry);
  return writePasswordEntries(entries, dataKey);
}

/**
 * Update a password entry by index
 */
export async function updatePasswordEntry(
  index: number,
  newPassword: string,
  dataKey: CryptoKey
): Promise<boolean> {
  const entries = await readPasswordEntries(dataKey);
  if (index < 0 || index >= entries.length) return false;

  entries[index].password = newPassword;
  return writePasswordEntries(entries, dataKey);
}

/**
 * Delete a password entry by index
 */
export async function deletePasswordEntry(
  index: number,
  dataKey: CryptoKey
): Promise<boolean> {
  const entries = await readPasswordEntries(dataKey);
  if (index < 0 || index >= entries.length) return false;

  entries.splice(index, 1);
  return writePasswordEntries(entries, dataKey);
}

/**
 * Search password entries
 */
export async function searchPasswordEntries(
  query: string,
  dataKey: CryptoKey
): Promise<PasswordEntry[]> {
  const entries = await readPasswordEntries(dataKey);
  const queryLower = query.toLowerCase();

  return entries.filter(
    (e) =>
      e.url.toLowerCase().includes(queryLower) ||
      e.username.toLowerCase().includes(queryLower) ||
      e.name.toLowerCase().includes(queryLower)
  );
}

/**
 * Export all entries as CSV content
 */
export async function exportToCSV(
  dataKey: CryptoKey
): Promise<string> {
  const entries = await readPasswordEntries(dataKey);
  const header = 'name,url,username,password,note';
  const rows = entries.map(
    (e) =>
      `"${e.name}","${e.url}","${e.username}","${e.password}","${e.note}"`
  );
  return [header, ...rows].join('\n');
}

/**
 * Import entries from CSV content
 */
export async function importFromCSV(
  csvContent: string,
  dataKey: CryptoKey
): Promise<{ imported: number; updated: number }> {
  const lines = csvContent.trim().split('\n');
  if (lines.length < 2) return { imported: 0, updated: 0 };

  const entries = await readPasswordEntries(dataKey);
  const existingMap = new Map(
    entries.map((e) => [`${e.url}||${e.username}`, e])
  );

  let imported = 0;
  let updated = 0;

  // Parse CSV (simple parser, handles quoted fields)
  const parseCSVLine = (line: string): string[] => {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        result.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    result.push(current);
    return result;
  };

  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    if (values.length < 4) continue;

    const [name, url, username, password, note = ''] = values;
    const key = `${url}||${username}`;

    if (existingMap.has(key)) {
      existingMap.get(key)!.password = password;
      updated++;
    } else {
      entries.push({ name, url, username, password, note });
      imported++;
    }
  }

  await writePasswordEntries(entries, dataKey);
  return { imported, updated };
}
