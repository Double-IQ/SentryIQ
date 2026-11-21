'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const endpoint = fs.readFileSync(path.join(root, 'app/Auth/GalleryPasskeyAuth.php'), 'utf8');
const keyStore = fs.readFileSync(path.join(root, 'cloud/Gallery/Storage/GalleryKeyStore.php'), 'utf8');
const ui = fs.readFileSync(path.join(root, 'assets/js/gallery_secure_ui.js'), 'utf8');
const secure = fs.readFileSync(path.join(root, 'assets/js/gallery_secure.js'), 'utf8');

test('Gallery device inventory exposes only enrolled credential identifiers and enrollment timestamps', () => {
    assert.match(endpoint, /\$_GET\['action'\]\s*\?\?\s*''\)\s*===\s*'devices'/);
    assert.match(endpoint, /\$galleryKeys->enrolledCredentialIds\(\)/);
    assert.match(endpoint, /'credentialId'\s*=>\s*\$credentialId/);
    assert.match(endpoint, /'createdAt'\s*=>\s*\(int\)/);
    const devicesBlock = endpoint.slice(endpoint.indexOf("=== 'devices'"), endpoint.indexOf("=== 'options'"));
    assert.ok(devicesBlock.length > 0, 'Device inventory route must be present.');
    assert.doesNotMatch(devicesBlock, /privateKeyEnvelope/);
});

test('removing a Gallery device requires a fresh different enrolled passkey', () => {
    assert.match(endpoint, /\$verifiedAt < time\(\) - 180/);
    assert.match(endpoint, /\$verifiedId === \$targetId/);
    assert.match(endpoint, /\$galleryKeys->credentialEnvelope\(\$verifiedId\) === null/);
    assert.match(endpoint, /\$galleryKeys->credentialEnvelope\(\$targetId\) === null/);
    assert.match(endpoint, /\$galleryKeys->removeCredentialEnvelope\(\$targetId\)/);
    assert.match(endpoint, /WebAuthn login credential remains registered/);
    assert.match(keyStore, /The last Gallery passkey envelope cannot be removed/);
    assert.match(secure, /action:\s*'remove_credential'/);
    assert.match(ui, /SentryIQSecureGallery\.removeEnrolledDevice/);
    assert.match(ui, /Its SentryIQ sign-in passkey will remain registered/);
});

test('Gallery device removal is not the global SentryIQ passkey deletion action', () => {
    assert.doesNotMatch(endpoint, /PasskeyAuth\.php/);
    assert.doesNotMatch(endpoint, /action\s*===\s*'delete'/);
});

test('WebAuthn signature counter cannot roll back to zero after becoming monotonic', () => {
    assert.match(endpoint, /if \(\$previousCounter !== 0 \|\| \$counter !== 0\)/);
    assert.match(endpoint, /if \(\$counter <= \$previousCounter\)/);
    assert.match(endpoint, /\$store\['credentials'\]\[\$index\]\['sign_count'\] = \$counter/);
    assert.match(endpoint, /Once a nonzero counter has been observed, a reset/);
});
