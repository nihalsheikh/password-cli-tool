/**
 * Build script for EigenVault Extension
 * Copies compiled JS to correct locations and creates ZIP packages
 */

import { copyFileSync, mkdirSync, rmSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { execSync } from 'child_process';

const args = process.argv.slice(2);
const isFirefox = args.includes('--firefox');
const isZip = args.includes('--zip');

const EXT_ROOT = process.cwd();
const BUILD_DIR = join(EXT_ROOT, isFirefox ? 'build-firefox' : 'build');

// Mapping of source files to output locations
const FILE_MAPPINGS = [
  { from: 'dist/background/service-worker.js', to: 'background/service-worker.js' },
  { from: 'dist/content/content-script.js', to: 'content/content-script.js' },
  { from: 'dist/core/crypto.js', to: 'core/crypto.js' },
  { from: 'dist/core/storage.js', to: 'core/storage.js' },
  { from: 'dist/core/password-gen.js', to: 'core/password-gen.js' },
  { from: 'dist/core/webauthn.js', to: 'core/webauthn.js' },
  { from: 'dist/dashboard/dashboard.js', to: 'dashboard/dashboard.js' },
  { from: 'dist/src/popup/popup.js', to: 'popup/popup.js' },
];

function ensureDir(dir) {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function copyFile(from, to) {
  const fullPath = join(EXT_ROOT, from);
  const destPath = join(BUILD_DIR, to);
  ensureDir(join(BUILD_DIR, dirname(to)));
  if (existsSync(fullPath)) {
    copyFileSync(fullPath, destPath);
    console.log(`Copied: ${from} -> ${to}`);
  } else {
    console.warn(`Warning: Source file not found: ${fullPath}`);
  }
}

function build() {
  console.log(`Building extension for ${isFirefox ? 'Firefox' : 'Chrome/Safari'}...`);

  // Clean build directory
  if (existsSync(BUILD_DIR)) {
    rmSync(BUILD_DIR, { recursive: true });
  }
  ensureDir(BUILD_DIR);

  // Copy manifest
  const manifestName = isFirefox ? 'manifest-firefox.json' : 'manifest.json';
  copyFileSync(join(EXT_ROOT, manifestName), join(BUILD_DIR, 'manifest.json'));
  console.log(`Copied: ${manifestName} -> manifest.json`);

  // Copy HTML and CSS files
  copyFileSync(join(EXT_ROOT, 'src/popup/popup.html'), join(BUILD_DIR, 'popup/popup.html'));
  copyFileSync(join(EXT_ROOT, 'src/popup/popup.css'), join(BUILD_DIR, 'popup/popup.css'));
  copyFileSync(join(EXT_ROOT, 'src/dashboard/dashboard.html'), join(BUILD_DIR, 'dashboard/dashboard.html'));
  copyFileSync(join(EXT_ROOT, 'src/dashboard/dashboard.css'), join(BUILD_DIR, 'dashboard/dashboard.css'));

  // Copy core, content, background files
  FILE_MAPPINGS.forEach(({ from, to }) => copyFile(from, to));

  // Create options page reference in manifest for dashboard
  console.log('\nBuild complete! Output in:', BUILD_DIR);

  if (isZip) {
    createZip();
  }
}

function createZip() {
  const zipName = isFirefox ? 'eigenvault-firefox.zip' : 'eigenvault-chrome.zip';
  const zipPath = join(EXT_ROOT, zipName);

  console.log('\nCreating ZIP package:', zipName);

  try {
    execSync(`cd "${BUILD_DIR}" && zip -r "${zipPath}" .`, { stdio: 'inherit' });
    console.log('ZIP created successfully!');
  } catch (e) {
    console.log('Note: zip command not available. Install zip utility or manually package the extension.');
  }
}

build();
