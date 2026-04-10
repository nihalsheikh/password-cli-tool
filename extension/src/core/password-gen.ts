/**
 * Password generation module
 * Ported from project.py with equivalent functionality
 */

import { getRandomBytes } from './crypto';

// Character sets matching Python string module
const ASCII_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ASCII_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const PUNCTUATION = '!@#$%^&*()_+-=[]{}|;:,.<>?';

// Regex for strong password validation (same as project.py)
const STRONG_PASSWORD_RE =
  /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9]).{8,}$/;

/**
 * Check if a password meets strong password requirements
 * Must contain: uppercase, lowercase, digit, special char, min 8 length
 */
export function isPasswordStrong(password: string): boolean {
  return STRONG_PASSWORD_RE.test(password);
}

/**
 * Generate a secure random password
 * Uses crypto.getRandomValues() (equivalent to Python's secrets module)
 */
export interface GeneratePasswordOptions {
  length?: number;
  useUppercase?: boolean;
  useLowercase?: boolean;
  useDigits?: boolean;
  useSpecial?: boolean;
  specialChars?: string;
}

export function generatePassword(
  options: GeneratePasswordOptions = {}
): string {
  const {
    length = 8,
    useUppercase = true,
    useLowercase = true,
    useDigits = true,
    useSpecial = true,
    specialChars = PUNCTUATION,
  } = options;

  // Validate minimum length
  if (length < 8) {
    throw new Error('For a strong password, length must be at least 8.');
  }

  // Build character pool and required characters
  let pool = '';
  const required: string[] = [];

  if (useUppercase) {
    pool += ASCII_UPPERCASE;
    required.push(getSecureRandomChar(ASCII_UPPERCASE));
  }
  if (useLowercase) {
    pool += ASCII_LOWERCASE;
    required.push(getSecureRandomChar(ASCII_LOWERCASE));
  }
  if (useDigits) {
    pool += DIGITS;
    required.push(getSecureRandomChar(DIGITS));
  }
  if (useSpecial) {
    pool += specialChars;
    required.push(getSecureRandomChar(specialChars));
  }

  // Validate at least one character set selected
  if (!pool) {
    throw new Error('At least one character set must be selected.');
  }

  // Handle edge case: length <= required characters
  if (length <= required.length) {
    return required.slice(0, length).join('');
  }

  // Fill remaining length with random characters from pool
  const remainingLength = length - required.length;
  const remainingChars: string[] = [];
  for (let i = 0; i < remainingLength; i++) {
    remainingChars.push(getSecureRandomChar(pool));
  }

  // Combine and shuffle using Fisher-Yates with secure random
  const passwordChars = [...required, ...remainingChars];
  secureShuffle(passwordChars);

  return passwordChars.join('');
}

/**
 * Get a cryptographically secure random character from a character set
 */
function getSecureRandomChar(charSet: string): string {
  const randomValue = getRandomBytes(1)[0];
  const index = randomValue % charSet.length;
  return charSet[index];
}

/**
 * Fisher-Yates shuffle using cryptographically secure random values
 */
function secureShuffle(array: string[]): void {
  for (let i = array.length - 1; i > 0; i--) {
    const randomBytes = getRandomBytes(4);
    const randomValue =
      (randomBytes[0] << 24) |
      (randomBytes[1] << 16) |
      (randomBytes[2] << 8) |
      randomBytes[3];
    const j = Math.abs(randomValue) % (i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
}

/**
 * Validate URL format (same regex as project.py)
 */
export function isValidUrl(url: string): boolean {
  const urlRegex = /^https?:\/\/(www\.)?[^/]+\.[a-zA-Z]{2,}(\/.*)?/;
  return urlRegex.test(url);
}

/**
 * Extract domain name from URL (same logic as _get_name_from_url in project.py)
 */
export function getNameFromUrl(url: string): string {
  let cleaned = url;

  // Strip protocol
  if (cleaned.includes('://')) {
    cleaned = cleaned.split('://', 1)[1];
  }

  // Strip path, query, and fragment
  cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0];

  // Remove trailing slash
  return cleaned.replace(/\/$/, '');
}

/**
 * Generate password suggestions with varying strength
 */
export function generatePasswordSuggestions(
  count: number = 3,
  length: number = 16
): string[] {
  const suggestions: string[] = [];

  for (let i = 0; i < count; i++) {
    suggestions.push(generatePassword({ length }));
  }

  return suggestions;
}

/**
 * Get password strength score (0-4 based on criteria met)
 */
export function getPasswordStrengthScore(password: string): {
  score: number;
  criteria: {
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasDigit: boolean;
    hasSpecial: boolean;
    hasMinLength: boolean;
  };
} {
  const criteria = {
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasDigit: /[0-9]/.test(password),
    hasSpecial: /[^a-zA-Z0-9]/.test(password),
    hasMinLength: password.length >= 8,
  };

  const score = Object.values(criteria).filter(Boolean).length;

  return { score, criteria };
}
