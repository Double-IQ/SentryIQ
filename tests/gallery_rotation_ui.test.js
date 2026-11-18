'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(
    path.join(__dirname, '../assets/js/gallery_secure_ui.js'),
    'utf8'
);

test('an in-progress rotation keeps its active target selectable for resume', () => {
    assert.match(source, /current && current\.status === 'running' && keyId === current\.to_key_id/);
    assert.match(source, /select\.value = current\.to_key_id/);
    assert.match(source, /byId\('secure-gallery-rotate'\)\.textContent = 'Resume rotation'/);
});
