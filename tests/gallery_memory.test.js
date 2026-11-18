'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const storage = fs.readFileSync(path.join(__dirname, '../assets/js/gallery_storage.js'), 'utf8');

test('decrypted metadata buffers are cleared after parsing', () => {
    assert.match(storage, /function decodePrivateMetadata\([\s\S]*?finally\s*\{[\s\S]*?metadataBytes\.fill\(0\)/);
});

test('decrypted image buffers are cleared after Blob creation', () => {
    assert.match(storage, /new Uint8Array\(thumbnailBytes\)\.fill\(0\)/);
    assert.match(storage, /new Uint8Array\(previewBytes\)\.fill\(0\)/);
});
