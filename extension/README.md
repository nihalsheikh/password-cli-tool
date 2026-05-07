# 🌐 EigenVault Browser Extension

<p align="center">
  <strong>The secure companion for your browser.</strong>
</p>

---

The **EigenVault** browser extension brings the power and security of your terminal vault directly into your web browsing experience. It provides secure password storage, intelligent auto-fill, and biometric unlock (FaceID/Fingerprint) for a seamless workflow.

## 🚀 Installation

### 1. Build the Extension
Before loading the extension into your browser, you need to compile the TypeScript source code:

```bash
cd extension
npm install
npm run build
```
This will create a `build/` directory with the compiled extension.

### 2. Load into Browser

#### 🟦 Chromium (Chrome, Arc, Brave, Vivaldi, Edge)
1. Open `chrome://extensions/` in your browser.
2. Enable **"Developer mode"** (toggle in the top right).
3. Click **"Load unpacked"**.
4. Select the `extension/build` folder.

#### 🦊 Firefox
1. Open `about:debugging#/runtime/this-firefox` in Firefox.
2. Click **"Load Temporary Add-on..."**.
3. Select the `manifest.json` file inside the `extension/build` folder.

#### 🧭 Safari
1. Enable the **Develop menu** in Safari (Settings > Advanced > Show features for web developers).
2. Go to **Develop > Allow Unsigned Extensions**.
3. Use the `xcrun safari-web-extension-converter` tool if you wish to package it for the App Store, or simply follow the [Apple Developer Documentation](https://developer.apple.com/documentation/safariservices/safari_web_extensions) for testing.

## 🔒 Key Features

- **Biometric Unlock**: Use your device's native biometric sensors to unlock your vault.
- **Smart Auto-fill**: Automatically detects login forms and suggests the correct credentials.
- **Context Menu Integration**: Right-click any input field to generate a secure password or trigger auto-fill.
- **Keyboard Shortcuts**:
  - `Ctrl+Shift+L` (Mac: `Cmd+Shift+L`): Open EigenVault Popup.
  - `Ctrl+Shift+F`: Trigger Auto-fill.
  - `Ctrl+Shift+G`: Generate a new password.

## 🛠️ Tech Stack

- **TypeScript**: Type-safe extension logic.
- **Web Crypto API**: Industry-standard encryption (AES-256-GCM) performed entirely client-side.
- **Manifest V3**: Compliant with the latest browser extension security standards.

## 📂 Development

The extension is organized as follows:
- `src/core/`: Cryptography and storage logic.
- `src/background/`: Service worker for session management.
- `src/content/`: Script for interacting with web pages (auto-fill).
- `src/popup/`: The main UI you see when clicking the extension icon.

---
<p align="center">
  Part of the 🛡️ <a href="../README.md">EigenVault</a> Security Suite.
</p>
