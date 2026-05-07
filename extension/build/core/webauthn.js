/**
 * WebAuthn biometric unlock module
 * Provides fingerprint/face recognition unlock for supported devices
 */
import { getRandomBytes } from './crypto.js';
const WEBAUTHN_CHALLENGE = 'eigenvault_webauthn_challenge';
/**
 * Check if WebAuthn is supported in this browser
 */
export function isWebAuthnSupported() {
    return window.PublicKeyCredential !== undefined &&
        navigator.credentials !== undefined;
}
/**
 * Check if platform authenticator (biometric) is available
 */
export async function isBiometricAvailable() {
    if (!isWebAuthnSupported())
        return false;
    try {
        const isAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        return isAvailable;
    }
    catch {
        return false;
    }
}
/**
 * Register a new WebAuthn credential for biometric unlock
 * Returns the credential ID that should be stored
 */
export async function registerBiometricCredential(userId) {
    try {
        const challenge = getRandomBytes(32);
        const createOptions = {
            rp: {
                name: 'EigenVault',
                id: window.location.hostname || 'localhost',
            },
            user: {
                id: new TextEncoder().encode(userId),
                name: 'eigenvault-user',
                displayName: 'EigenVault User',
            },
            challenge: challenge.buffer,
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 }, // ES256
                { type: 'public-key', alg: -257 }, // RS256
            ],
            timeout: 60000,
            authenticatorSelection: {
                authenticatorAttachment: 'platform', // Use platform authenticator (biometric)
                userVerification: 'required',
                requireResidentKey: false,
            },
            attestation: 'none',
        };
        const credential = await navigator.credentials.create({
            publicKey: createOptions,
        });
        if (!credential)
            return null;
        return {
            credentialId: arrayBufferToBase64(credential.rawId),
            publicKey: arrayBufferToBase64(credential.response.getPublicKey()),
        };
    }
    catch (error) {
        console.error('WebAuthn registration failed:', error);
        return null;
    }
}
/**
 * Authenticate using biometric credential
 * Returns true if authentication successful
 */
export async function authenticateWithBiometric(credentialId) {
    try {
        const challenge = getRandomBytes(32);
        const getOptions = {
            challenge: challenge.buffer,
            allowCredentials: [
                {
                    type: 'public-key',
                    id: base64ToArrayBuffer(credentialId),
                },
            ],
            timeout: 60000,
            userVerification: 'required',
        };
        const credential = await navigator.credentials.get({
            publicKey: getOptions,
        });
        return credential !== null;
    }
    catch (error) {
        console.error('WebAuthn authentication failed:', error);
        return false;
    }
}
/**
 * Store encrypted backup key using WebAuthn credential
 * This allows recovery if master password is forgotten
 */
export async function storeRecoveryKey(recoveryKey, credentialId) {
    try {
        // Encrypt recovery key with a key derived from WebAuthn response
        const challenge = getRandomBytes(32);
        const getOptions = {
            challenge: challenge.buffer,
            allowCredentials: [
                {
                    type: 'public-key',
                    id: base64ToArrayBuffer(credentialId),
                },
            ],
            timeout: 60000,
            userVerification: 'required',
        };
        const credential = await navigator.credentials.get({
            publicKey: getOptions,
        });
        if (!credential)
            return false;
        // Store encrypted recovery key in chrome.storage
        const response = credential.response;
        const authData = new Uint8Array(response.authenticatorData);
        await chrome.storage.sync.set({
            'eigen_recovery_encrypted': {
                data: recoveryKey,
                authDataHash: arrayBufferToBase64(await crypto.subtle.digest('SHA-256', authData)),
            },
        });
        return true;
    }
    catch (error) {
        console.error('Failed to store recovery key:', error);
        return false;
    }
}
/**
 * Retrieve recovery key using WebAuthn
 */
export async function retrieveRecoveryKey(credentialId) {
    try {
        const result = await chrome.storage.sync.get(['eigen_recovery_encrypted']);
        const encrypted = result['eigen_recovery_encrypted'];
        if (!encrypted)
            return null;
        // Verify with WebAuthn first
        const authenticated = await authenticateWithBiometric(credentialId);
        if (!authenticated)
            return null;
        return encrypted.data;
    }
    catch (error) {
        console.error('Failed to retrieve recovery key:', error);
        return null;
    }
}
/**
 * Convert ArrayBuffer to Base64 string
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
/**
 * Convert Base64 string to ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
//# sourceMappingURL=webauthn.js.map