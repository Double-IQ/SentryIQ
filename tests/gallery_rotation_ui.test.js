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
    assert.match(source, /\['running', 'ready_to_retire'\]\.includes\(current\.status\)/);
    assert.match(source, /select\.value = current\.to_key_id/);
    assert.match(source, /byId\('secure-gallery-rotate'\)\.textContent = 'Resume rotation'/);
});

test('a completed migration retains the old key through its rollback window', () => {
    assert.match(source, /current && current\.status === 'ready_to_retire'/);
    assert.match(source, /Finalize key retirement/);
    assert.match(source, /retained for rollback until/);
});
