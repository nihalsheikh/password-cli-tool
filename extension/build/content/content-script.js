/**
 * Content Script for EigenVault
 * Handles form detection, bot trap avoidance, and auto-fill
 */
// Field detection patterns
const USERNAME_PATTERNS = [
    'username', 'user', 'login', 'email', 'userid', 'user_id',
    'account', 'name', 'fullname', 'full_name', 'first_name', 'last_name',
    'firstname', 'lastname', 'given_name', 'family_name', 'nickname'
];
const PASSWORD_PATTERNS = [
    'password', 'passwd', 'pass', 'pwd', 'secret', 'pin', 'credential'
];
const EMAIL_PATTERNS = [
    'email', 'e-mail', 'mail', 'emailaddress', 'email_address'
];
// Bot trap patterns - fields that should NOT be filled
const BOT_TRAP_PATTERNS = [
    'honeypot', 'hp_', 'trap', 'fake', 'bot', 'spam',
    'website_url', 'homepage', 'company_url', 'subject',
    'message', 'comment', 'phone', 'address', 'city', 'state', 'zip'
];
// Special autocomplete values
const AUTOCOMPLETE_USERNAME = ['username', 'email', 'tel', 'nickname'];
const AUTOCOMPLETE_PASSWORD = ['current-password', 'new-password'];
// State
let hasAutoFilled = false;
const detectedForms = new Map();
/**
 * Initialize content script
 */
function init() {
    console.log('[EigenVault] Content script loaded');
    // Detect forms on page load
    detectForms();
    // Try to disable browser autofill
    disableBrowserAutofill();
    // Check for saved credentials and auto-fill if possible
    setTimeout(checkAndAutoFill, 1000);
    // Listen for messages from background/popup
    chrome.runtime.onMessage.addListener(handleMessage);
    // Watch for dynamically added forms
    observeDOM();
    // Re-attach listeners periodically to ensure new fields are caught
    setInterval(detectForms, 3000);
}
/**
 * Handle messages from extension
 */
function handleMessage(message, sender, sendResponse) {
    switch (message.type) {
        case 'FILL_CREDENTIALS':
            fillCredentials(message.username, message.password);
            sendResponse({ success: true });
            break;
        case 'FILL_PASSWORD':
            fillPassword(message.password);
            sendResponse({ success: true });
            break;
        case 'TRIGGER_AUTOFILL':
            checkAndAutoFill(); // Trigger the check again
            sendResponse({ success: true });
            break;
        case 'SHOW_CREDENTIAL_PICKER':
            // Force show picker if we have matches
            checkAndAutoFill(true);
            sendResponse({ success: true });
            break;
        case 'GET_DETECTED_FORMS':
            sendResponse({ forms: getFormsInfo() });
            break;
        default:
            sendResponse({ error: 'Unknown message type' });
    }
    return true; // Keep channel open for async response
}
/**
 * Suppress browser's built-in password manager
 */
function disableBrowserAutofill() {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        // Setting autocomplete to off or a random string can help prevent browser autofill
        // Some browsers ignore "off", so we use more specific values or random strings
        if (input.type === 'password') {
            input.setAttribute('autocomplete', 'new-password'); // Often prevents browser from filling "current" password
        }
        else {
            input.setAttribute('autocomplete', 'one-time-code'); // Another value that browsers often respect as "don't autofill"
        }
        // Some browsers also look for these attributes
        input.setAttribute('data-eigenvault-managed', 'true');
    });
}
/**
 * Check if vault is unlocked and if we have matching credentials to auto-fill
 */
async function checkAndAutoFill(forceShow = false) {
    if (hasAutoFilled && !forceShow)
        return;
    try {
        const unlockedResponse = await chrome.runtime.sendMessage({ type: 'CHECK_UNLOCKED' });
        if (unlockedResponse && unlockedResponse.unlocked) {
            const response = await chrome.runtime.sendMessage({ type: 'GET_MATCHING_ENTRIES' });
            if (response && response.matches && response.matches.length > 0) {
                // If only one match, we can auto-fill automatically
                if (response.matches.length === 1 && !forceShow) {
                    const entry = response.matches[0];
                    detectForms();
                    if (detectedForms.size > 0) {
                        console.log(`[EigenVault] Auto-filling credentials for ${entry.username}`);
                        fillCredentials(entry.username, entry.password);
                        hasAutoFilled = true;
                    }
                }
                else {
                    // Multiple matches: show picker when fields are focused
                    console.log(`[EigenVault] ${response.matches.length} matches found. Showing picker on focus.`);
                    attachPickerListeners(response.matches);
                    if (forceShow) {
                        const activeInput = document.activeElement;
                        if (activeInput && (activeInput.tagName === 'INPUT' || activeInput.hasAttribute('data-eigenvault-detected'))) {
                            showCredentialPicker(activeInput, response.matches);
                        }
                    }
                }
            }
        }
    }
    catch (error) {
        console.error('[EigenVault] Error during auto-fill check:', error);
    }
}
/**
 * Attach focus listeners to show picker
 */
function attachPickerListeners(matches) {
    const inputs = document.querySelectorAll('[data-eigenvault-detected]');
    inputs.forEach(input => {
        input.addEventListener('focus', () => {
            showCredentialPicker(input, matches);
        });
    });
}
/**
 * Show a floating credential picker near an input
 */
function showCredentialPicker(input, matches) {
    // Remove existing picker if any
    removeCredentialPicker();
    const picker = document.createElement('div');
    picker.id = 'eigenvault-picker';
    picker.style.cssText = `
    position: absolute;
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    z-index: 9999999;
    width: 250px;
    max-height: 200px;
    overflow-y: auto;
    padding: 8px;
    animation: evFadeIn 0.2s ease;
  `;
    // Position the picker
    const rect = input.getBoundingClientRect();
    const scrollY = window.scrollY;
    picker.style.top = `${rect.bottom + scrollY + 5}px`;
    picker.style.left = `${rect.left}px`;
    // Header
    const header = document.createElement('div');
    header.style.cssText = `
    font-size: 11px;
    font-weight: 700;
    color: #94a3b8;
    padding: 4px 8px 8px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  `;
    header.textContent = 'Select Account';
    picker.appendChild(header);
    // List matches
    matches.forEach(match => {
        const item = document.createElement('div');
        item.style.cssText = `
      padding: 10px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      gap: 2px;
      transition: background 0.2s;
    `;
        item.innerHTML = `
      <div style="font-weight: 600; font-size: 13px; color: #f8fafc;">${match.name || 'Account'}</div>
      <div style="font-size: 12px; color: #94a3b8;">${match.username}</div>
    `;
        item.addEventListener('mouseenter', () => item.style.background = '#334155');
        item.addEventListener('mouseleave', () => item.style.background = 'transparent');
        item.addEventListener('mousedown', (e) => {
            e.preventDefault(); // Prevent focus loss
            fillCredentials(match.username, match.password);
            removeCredentialPicker();
            hasAutoFilled = true;
        });
        picker.appendChild(item);
    });
    document.body.appendChild(picker);
    // Close picker when clicking elsewhere
    const handleOutsideClick = (e) => {
        if (!picker.contains(e.target) && e.target !== input) {
            removeCredentialPicker();
            document.removeEventListener('mousedown', handleOutsideClick);
        }
    };
    document.addEventListener('mousedown', handleOutsideClick);
}
/**
 * Remove existing picker
 */
function removeCredentialPicker() {
    const existing = document.getElementById('eigenvault-picker');
    if (existing)
        existing.remove();
}
/**
 * Detect all forms on the page
 */
function detectForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach((form, index) => {
        const detected = analyzeForm(form);
        if (detected.fields.length > 0) {
            detectedForms.set(index, detected);
            highlightDetectedFields(detected);
        }
    });
    // Also look for inputs not wrapped in a form
    const looseInputs = Array.from(document.querySelectorAll('input')).filter(input => !input.form);
    if (looseInputs.length > 0) {
        const virtualForm = {
            form: null,
            fields: [],
            hasBotTraps: false
        };
        looseInputs.forEach(input => {
            const fieldInfo = determineFieldType(input);
            if (fieldInfo)
                virtualForm.fields.push(fieldInfo);
        });
        if (virtualForm.fields.length > 0) {
            detectedForms.set(-1, virtualForm);
        }
    }
}
/**
 * Analyze a form for username/password fields
 */
function analyzeForm(form) {
    const inputs = form.querySelectorAll('input');
    const fields = [];
    let hasBotTraps = false;
    inputs.forEach((input) => {
        // Skip hidden, submit, button, checkbox, radio types
        const skipTypes = ['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image'];
        if (skipTypes.includes(input.type))
            return;
        // Check for bot traps
        if (isBotTrap(input)) {
            hasBotTraps = true;
            markAsBotTrap(input);
            return;
        }
        // Determine field type
        const fieldInfo = determineFieldType(input);
        if (fieldInfo) {
            fields.push(fieldInfo);
        }
    });
    return {
        form,
        fields,
        hasBotTraps,
    };
}
/**
 * Determine the type of a form field
 */
function determineFieldType(input) {
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const autocomplete = (input.autocomplete || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const type = input.type.toLowerCase();
    // Check type attribute first (strongest signal)
    if (type === 'password') {
        return { element: input, type: 'password', confidence: 0.95 };
    }
    if (type === 'email') {
        return { element: input, type: 'email', confidence: 0.9 };
    }
    // Check autocomplete attribute
    if (autocomplete) {
        if (AUTOCOMPLETE_USERNAME.some((p) => autocomplete.includes(p))) {
            return { element: input, type: 'username', confidence: 0.95 };
        }
        if (AUTOCOMPLETE_PASSWORD.some((p) => autocomplete.includes(p))) {
            return { element: input, type: 'password', confidence: 0.95 };
        }
        if (autocomplete === 'email') {
            return { element: input, type: 'email', confidence: 0.95 };
        }
    }
    // Check name, id, placeholder patterns
    const identifiers = [name, id, placeholder].join(' ');
    if (PASSWORD_PATTERNS.some((p) => identifiers.includes(p))) {
        return { element: input, type: 'password', confidence: 0.85 };
    }
    if (EMAIL_PATTERNS.some((p) => identifiers.includes(p))) {
        return { element: input, type: 'email', confidence: 0.85 };
    }
    if (USERNAME_PATTERNS.some((p) => identifiers.includes(p))) {
        return { element: input, type: 'username', confidence: 0.8 };
    }
    // Check nearby labels
    const label = findAssociatedLabel(input);
    if (label) {
        const labelText = label.textContent?.toLowerCase() || '';
        if (PASSWORD_PATTERNS.some((p) => labelText?.includes(p))) {
            return { element: input, type: 'password', confidence: 0.85 };
        }
        if (EMAIL_PATTERNS.some((p) => labelText?.includes(p))) {
            return { element: input, type: 'email', confidence: 0.85 };
        }
        if (USERNAME_PATTERNS.some((p) => labelText?.includes(p))) {
            return { element: input, type: 'username', confidence: 0.75 };
        }
    }
    return null;
}
/**
 * Check if a field is a bot trap
 */
function isBotTrap(input) {
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const classList = Array.from(input.classList).join(' ').toLowerCase();
    const identifiers = [name, id, placeholder, classList].join(' ');
    // Check against bot trap patterns
    if (BOT_TRAP_PATTERNS.some((p) => identifiers.includes(p))) {
        return true;
    }
    // Check for hidden fields (common bot trap technique)
    const style = window.getComputedStyle(input);
    if (style.display === 'none' ||
        style.visibility === 'hidden' ||
        (input.offsetParent === null && input.type !== 'hidden')) {
        // Additional check: is it really needed for the form?
        if (!USERNAME_PATTERNS.some((p) => identifiers.includes(p)) &&
            !PASSWORD_PATTERNS.some((p) => identifiers.includes(p)) &&
            !EMAIL_PATTERNS.some((p) => identifiers.includes(p))) {
            return true;
        }
    }
    // Check for off-screen positioning (another bot trap technique)
    const rect = input.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
        // But don't mark it if it looks like a legitimate password field that might be revealed
        if (input.type === 'password')
            return false;
        return true;
    }
    return false;
}
/**
 * Mark a field as a bot trap visually (for debugging)
 */
function markAsBotTrap(input) {
    // input.style.borderColor = 'red';
    // input.style.borderWidth = '2px';
    // input.title = 'Bot trap field - not filling';
}
/**
 * Find label associated with an input
 */
function findAssociatedLabel(input) {
    // Check for label wrapping the input
    const parentLabel = input.closest('label');
    if (parentLabel)
        return parentLabel;
    // Check for label with for attribute
    if (input.id) {
        const label = document.querySelector(`label[for="${input.id}"]`);
        if (label)
            return label;
    }
    return null;
}
/**
 * Highlight detected fields with visual indicator
 */
function highlightDetectedFields(detected) {
    detected.fields.forEach((field) => {
        if (field.type === 'username' || field.type === 'email' || field.type === 'password') {
            field.element.setAttribute('data-eigenvault-detected', field.type);
        }
    });
}
/**
 * Fill credentials into detected form
 */
function fillCredentials(username, password) {
    // Try to find forms again to ensure we have the latest
    detectForms();
    // Get all forms
    const allForms = Array.from(detectedForms.values());
    // If no forms found, or only loose inputs, handle specially
    if (allForms.length === 0) {
        fillLooseInputs(username, password);
        return;
    }
    // Prioritize forms with both username and password fields
    allForms.sort((a, b) => {
        const aHasPass = a.fields.some(f => f.type === 'password');
        const bHasPass = b.fields.some(f => f.type === 'password');
        const aHasUser = a.fields.some(f => f.type === 'username' || f.type === 'email');
        const bHasUser = b.fields.some(f => f.type === 'username' || f.type === 'email');
        const aScore = (aHasPass ? 2 : 0) + (aHasUser ? 1 : 0);
        const bScore = (bHasPass ? 2 : 0) + (bHasUser ? 1 : 0);
        return bScore - aScore;
    });
    const targetForm = allForms[0];
    let filledCount = 0;
    // Track if we've filled a field type to avoid double-filling if multiple fields detected
    const filledTypes = new Set();
    for (const field of targetForm.fields) {
        if ((field.type === 'username' || field.type === 'email') && username && !filledTypes.has('username')) {
            setFieldValue(field.element, username);
            filledCount++;
            filledTypes.add('username');
        }
        else if (field.type === 'password' && password && !filledTypes.has('password')) {
            setFieldValue(field.element, password);
            filledCount++;
            filledTypes.add('password');
        }
    }
    // If we still haven't filled password but target form was missing it, look elsewhere
    if (!filledTypes.has('password') && password) {
        const passInputs = document.querySelectorAll('input[type="password"]');
        if (passInputs.length > 0) {
            setFieldValue(passInputs[0], password);
            filledCount++;
        }
    }
    if (filledCount > 0) {
        showFillNotification(filledCount);
    }
}
/**
 * Fallback to fill inputs not explicitly in a form
 */
function fillLooseInputs(username, password) {
    const userInputs = document.querySelectorAll('input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"])');
    const passInputs = document.querySelectorAll('input[type="password"]');
    let filled = 0;
    // Try to find the "best" username input
    let bestUserInput = null;
    for (const input of Array.from(userInputs)) {
        const type = determineFieldType(input);
        if (type && (type.type === 'username' || type.type === 'email')) {
            bestUserInput = input;
            break;
        }
    }
    if (bestUserInput && username) {
        setFieldValue(bestUserInput, username);
        filled++;
    }
    else if (userInputs.length > 0 && username) {
        setFieldValue(userInputs[0], username);
        filled++;
    }
    if (passInputs.length > 0 && password) {
        setFieldValue(passInputs[0], password);
        filled++;
    }
    if (filled > 0)
        showFillNotification(filled);
}
/**
 * Set input value and trigger necessary events for modern web apps (React, Vue, etc.)
 */
function setFieldValue(input, value) {
    // Focus first
    input.focus();
    // Clear existing value
    input.value = '';
    // React-specific value setter bypass
    const nativeValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    if (nativeValueSetter && nativeValueSetter !== Object.getOwnPropertyDescriptor(input, 'value')?.set) {
        nativeValueSetter.call(input, value);
    }
    else {
        input.value = value;
    }
    // Create and dispatch events
    const inputEvent = new Event('input', { bubbles: true, cancelable: true });
    const changeEvent = new Event('change', { bubbles: true, cancelable: true });
    input.dispatchEvent(inputEvent);
    input.dispatchEvent(changeEvent);
    // For some sites, we need to dispatch a keyboard event or simulate typing
    const keyEvent = new KeyboardEvent('keydown', { bubbles: true, cancelable: true, key: 'a' });
    input.dispatchEvent(keyEvent);
    // Blur to finalize
    input.blur();
}
/**
 * Fill only password (for generate password flow)
 */
function fillPassword(password) {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
        setFieldValue(passwordFields[0], password);
        showFillNotification(1);
    }
    else {
        console.warn('[EigenVault] No password field found');
    }
}
/**
 * Trigger auto-fill UI
 */
function triggerAutoFill() {
    // Send message to popup to show credential picker
    chrome.runtime.sendMessage({ type: 'SHOW_CREDENTIAL_PICKER' });
}
/**
 * Show notification after filling
 */
function showFillNotification(fieldCount) {
    // Check if notification already exists to avoid duplicates
    if (document.getElementById('eigenvault-notification'))
        return;
    const notification = document.createElement('div');
    notification.id = 'eigenvault-notification';
    notification.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: linear-gradient(135deg, #6366f1, #a855f7);
    color: white;
    padding: 16px 24px;
    border-radius: 12px;
    font-size: 14px;
    font-weight: 600;
    box-shadow: 0 10px 40px rgba(99, 102, 241, 0.4);
    z-index: 9999999;
    animation: evSlideIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    display: flex;
    align-items: center;
    gap: 12px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    pointer-events: none;
  `;
    notification.innerHTML = `
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
    </svg>
    <span>Filled ${fieldCount} field(s)</span>
  `;
    document.body.appendChild(notification);
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'evSlideOut 0.3s ease forwards';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
/**
 * Get info about detected forms (for debugging)
 */
function getFormsInfo() {
    const info = [];
    for (const [index, form] of detectedForms.entries()) {
        info.push({
            index,
            fieldCount: form.fields.length,
            hasBotTraps: form.hasBotTraps,
            fields: form.fields.map((f) => ({
                type: f.type,
                name: f.element.name,
                id: f.element.id,
                confidence: f.confidence,
            })),
        });
    }
    return info;
}
/**
 * Observe DOM for dynamically added forms
 */
function observeDOM() {
    const observer = new MutationObserver((mutations) => {
        let shouldDetect = false;
        for (const mutation of mutations) {
            if (mutation.addedNodes.length > 0) {
                for (const node of mutation.addedNodes) {
                    if (node.nodeName === 'FORM' || node.querySelector?.('form') || node.nodeName === 'INPUT') {
                        shouldDetect = true;
                        break;
                    }
                }
            }
        }
        if (shouldDetect) {
            // Debounce detection
            clearTimeout(window._evDetectTimeout);
            window._evDetectTimeout = setTimeout(() => {
                detectForms();
                disableBrowserAutofill();
                if (!hasAutoFilled)
                    checkAndAutoFill();
            }, 500);
        }
    });
    observer.observe(document.body, {
        childList: true,
        subtree: true,
    });
}
// Add animation styles
const style = document.createElement('style');
style.textContent = `
  @keyframes evSlideIn {
    from { transform: translateX(120%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes evSlideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(120%); opacity: 0; }
  }
  @keyframes evFadeIn {
    from { opacity: 0; transform: translateY(-5px); }
    to { opacity: 1; transform: translateY(0); }
  }
  [data-eigenvault-detected] {
    transition: box-shadow 0.3s ease;
  }
  [data-eigenvault-detected]:focus {
    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.4) ! from;
  }
`;
document.head.appendChild(style);
// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
}
else {
    init();
}
//# sourceMappingURL=content-script.js.map