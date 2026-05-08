/**
 * Minimal TOTP (Time-based One-Time Password) implementation
 * Using Web Crypto API (HMAC-SHA1)
 */

/**
 * Convert Base32 string to Uint8Array
 */
function base32ToBytes(base32: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = base32.replace(/=+$/, '').toUpperCase();
  const bytes = new Uint8Array(Math.floor((clean.length * 5) / 8));

  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean[i]);
    if (val === -1) continue;

    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bytes[index++] = (value >> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return bytes;
}

/**
 * Generate a random Base32 secret
 */
export function generateSecret(length = 16): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const random = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(random)
    .map((b) => alphabet[b % 32])
    .join('');
}

/**
 * Generate TOTP code
 */
export async function generateTOTP(secret: string, timeStep = 30): Promise<string> {
  const key = base32ToBytes(secret);
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  
  // Convert counter to 8-byte big-endian buffer
  const counterBuf = new Uint8Array(8);
  let tmpCounter = counter;
  for (let i = 7; i >= 0; i--) {
    counterBuf[i] = tmpCounter & 0xff;
    tmpCounter = Math.floor(tmpCounter / 256);
  }

  // Import key for HMAC
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    key.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  // Sign counter
  const signature = await crypto.subtle.sign('HMAC', hmacKey, counterBuf);
  const hash = new Uint8Array(signature);

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0xf;
  const code =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const finalCode = (code % 1000000).toString().padStart(6, '0');
  return finalCode;
}

/**
 * Verify TOTP code (with window for clock drift)
 */
export async function verifyTOTP(
  secret: string,
  code: string,
  window = 1
): Promise<boolean> {
  const currentTime = Math.floor(Date.now() / 1000);
  
  for (let i = -window; i <= window; i++) {
    const testTime = currentTime + i * 30;
    const testCode = await generateTOTPAtTime(secret, testTime);
    if (testCode === code) return true;
  }
  
  return false;
}

async function generateTOTPAtTime(secret: string, time: number): Promise<string> {
  const key = base32ToBytes(secret);
  const counter = Math.floor(time / 30);
  
  const counterBuf = new Uint8Array(8);
  let tmpCounter = counter;
  for (let i = 7; i >= 0; i--) {
    counterBuf[i] = tmpCounter & 0xff;
    tmpCounter = Math.floor(tmpCounter / 256);
  }

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    key.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', hmacKey, counterBuf);
  const hash = new Uint8Array(signature);

  const offset = hash[hash.length - 1] & 0xf;
  const code =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, '0');
}
