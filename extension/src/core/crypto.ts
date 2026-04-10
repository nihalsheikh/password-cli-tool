/**
 * Crypto module using Web Crypto API for secure password manager operations
 * Implements PBKDF2 key derivation and AES-GCM encryption
 */

// Constants
const PBKDF2_ITERATIONS = 150000; // OWASP recommended minimum
const SALT_LENGTH = 32; // bytes
const KEY_LENGTH = 256; // bits
const IV_LENGTH = 12; // bytes (96 bits for GCM)
const TAG_LENGTH = 128; // bits

/**
 * Generate cryptographically secure random bytes
 */
export function getRandomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

/**
 * Derive a key from a password using PBKDF2
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate a new salt for key derivation
 */
export function generateSalt(): Uint8Array {
  return getRandomBytes(SALT_LENGTH);
}

/**
 * Encrypt data using AES-GCM
 * @param data - The plaintext data to encrypt
 * @param key - The AES-GCM key
 * @returns Object containing encrypted data and IV
 */
export async function encrypt(
  data: string,
  key: CryptoKey
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const iv = getRandomBytes(IV_LENGTH);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: TAG_LENGTH,
    },
    key,
    dataBuffer
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv,
  };
}

/**
 * Decrypt data using AES-GCM
 * @param ciphertext - The encrypted data
 * @param iv - The initialization vector
 * @param key - The AES-GCM key
 * @returns The decrypted plaintext
 */
export async function decrypt(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  key: CryptoKey
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: TAG_LENGTH,
    },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Export a key to raw bytes for storage
 */
export async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  const exported = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(exported);
}

/**
 * Import a key from raw bytes
 */
export async function importKey(keyData: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyData,
    'AES-GCM',
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Hash data using SHA-256 (for verification purposes)
 */
export async function hashData(data: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hash = await crypto.subtle.digest('SHA-256', dataBuffer);
  return new Uint8Array(hash);
}

/**
 * Verify a password against a stored hash
 */
export async function verifyPassword(
  password: string,
  storedHash: Uint8Array
): Promise<boolean> {
  const computedHash = await hashData(password);
  if (computedHash.length !== storedHash.length) return false;
  return computedHash.every((byte, i) => byte === storedHash[i]);
}
