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

interface FormField {
  element: HTMLInputElement;
  type: 'username' | 'password' | 'email' | 'unknown';
  confidence: number;
}

interface DetectedForm {
  form: HTMLFormElement;
  fields: FormField[];
  hasBotTraps: boolean;
}

// Store detected forms
const detectedForms: Map<number, DetectedForm> = new Map();

/**
 * Initialize content script
 */
function init() {
  console.log('[EigenVault] Content script loaded');

  // Detect forms on page load
  detectForms();

  // Listen for messages from background/popup
  chrome.runtime.onMessage.addListener(handleMessage);

  // Watch for dynamically added forms
  observeDOM();
}

/**
 * Handle messages from extension
 */
function handleMessage(message: { type: string; [key: string]: unknown }, sender: chrome.runtime.MessageSender, sendResponse: (response: unknown) => void) {
  switch (message.type) {
    case 'FILL_CREDENTIALS':
      fillCredentials(message.username as string, message.password as string);
      sendResponse({ success: true });
      break;

    case 'FILL_PASSWORD':
      fillPassword(message.password as string);
      sendResponse({ success: true });
      break;

    case 'TRIGGER_AUTOFILL':
      triggerAutoFill();
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
 * Detect all forms on the page
 */
function detectForms() {
  const forms = document.querySelectorAll('form');

  forms.forEach((form, index) => {
    const detected = analyzeForm(form as HTMLFormElement);
    if (detected.fields.length > 0) {
      detectedForms.set(index, detected);
      highlightDetectedFields(detected);
    }
  });
}

/**
 * Analyze a form for username/password fields
 */
function analyzeForm(form: HTMLFormElement): DetectedForm {
  const inputs = form.querySelectorAll('input') as NodeListOf<HTMLInputElement>;
  const fields: FormField[] = [];
  let hasBotTraps = false;

  inputs.forEach((input) => {
    // Skip hidden, submit, button, checkbox, radio types
    const skipTypes = ['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image'];
    if (skipTypes.includes(input.type)) return;

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
function determineFieldType(input: HTMLInputElement): FormField | null {
  const name = (input.name || '').toLowerCase();
  const id = (input.id || '').toLowerCase();
  const autocomplete = (input.autocomplete || '').toLowerCase();
  const placeholder = (input.placeholder || '').toLowerCase();
  const type = input.type.toLowerCase();

  // Check autocomplete attribute first (most reliable)
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

  // Check type attribute
  if (type === 'email') {
    return { element: input, type: 'email', confidence: 0.9 };
  }
  if (type === 'password') {
    return { element: input, type: 'password', confidence: 0.9 };
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
function isBotTrap(input: HTMLInputElement): boolean {
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
  if (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    (input.offsetParent === null && input.type !== 'hidden')
  ) {
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
    return true;
  }

  return false;
}

/**
 * Mark a field as a bot trap visually (for debugging)
 */
function markAsBotTrap(input: HTMLInputElement) {
  input.style.borderColor = 'red';
  input.style.borderWidth = '2px';
  input.title = 'Bot trap field - not filling';
}

/**
 * Find label associated with an input
 */
function findAssociatedLabel(input: HTMLInputElement): HTMLLabelElement | null {
  // Check for label wrapping the input
  const parentLabel = input.closest('label') as HTMLLabelElement;
  if (parentLabel) return parentLabel;

  // Check for label with for attribute
  if (input.id) {
    const label = document.querySelector(`label[for="${input.id}"]`) as HTMLLabelElement;
    if (label) return label;
  }

  return null;
}

/**
 * Highlight detected fields with visual indicator
 */
function highlightDetectedFields(detected: DetectedForm) {
  detected.fields.forEach((field) => {
    if (field.type === 'username' || field.type === 'email') {
      field.element.style.borderColor = 'var(--primary, #6366f1)';
      field.element.style.borderWidth = '2px';
    }
  });
}

/**
 * Fill credentials into detected form
 */
function fillCredentials(username: string, password: string) {
  // Find the primary form on page
  const primaryForm = detectedForms.values().next().value;
  if (!primaryForm) {
    console.warn('[EigenVault] No form detected');
    return;
  }

  let usernameField: HTMLInputElement | null = null;
  let passwordField: HTMLInputElement | null = null;

  // Find best matching fields
  for (const field of primaryForm.fields) {
    if ((field.type === 'username' || field.type === 'email') && !usernameField) {
      usernameField = field.element;
    }
    if (field.type === 'password' && !passwordField) {
      passwordField = field.element;
    }
  }

  // Fill username
  if (usernameField) {
    simulateUserInput(usernameField, username);
  }

  // Fill password (with slight delay for realism)
  if (passwordField && password) {
    setTimeout(() => {
      simulateUserInput(passwordField, password);
    }, 100);
  }

  // Show success notification
  showFillNotification(primaryForm.fields.length);
}

/**
 * Fill only password (for generate password flow)
 */
function fillPassword(password: string) {
  // Find any password field on page
  const passwordFields = document.querySelectorAll('input[type="password"]') as NodeListOf<HTMLInputElement>;

  if (passwordFields.length > 0) {
    // Fill the first password field (usually "new password")
    simulateUserInput(passwordFields[0], password);
    showFillNotification(1);
  } else {
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
 * Simulate realistic user input
 */
function simulateUserInput(input: HTMLInputElement, value: string) {
  // Focus the input
  input.focus();
  input.click();

  // Set value character by character for realism
  let charIndex = 0;
  const interval = setInterval(() => {
    if (charIndex < value.length) {
      input.value += value[charIndex];
      charIndex++;

      // Dispatch input events
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      clearInterval(interval);
      input.blur();
    }
  }, 30); // 30ms per character
}

/**
 * Show notification after filling
 */
function showFillNotification(fieldCount: number) {
  // Create notification element
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: linear-gradient(135deg, #6366f1, #a855f7);
    color: white;
    padding: 16px 24px;
    border-radius: 12px;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 10px 40px rgba(99, 102, 241, 0.4);
    z-index: 999999;
    animation: slideIn 0.3s ease;
  `;

  notification.textContent = `✓ Filled ${fieldCount} field(s)`;
  document.body.appendChild(notification);

  // Remove after 3 seconds
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
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
          if (node.nodeName === 'FORM' || (node as Element).querySelector?.('form')) {
            shouldDetect = true;
            break;
          }
        }
      }
    }

    if (shouldDetect) {
      // Debounce detection
      clearTimeout((window as unknown as { _evDetectTimeout?: number })._evDetectTimeout);
      (window as unknown as { _evDetectTimeout?: number })._evDetectTimeout = setTimeout(detectForms, 500);
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
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
`;
document.head.appendChild(style);

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
