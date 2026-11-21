'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const page = fs.readFileSync(path.join(__dirname, '../app/Gallery/SecurePage.php'), 'utf8');
const navigation = fs.readFileSync(path.join(__dirname, '../assets/js/sentryiq_navigation.js'), 'utf8');

test('Secure Gallery CSP does not permit inline JavaScript', () => {
    assert.match(page, /script-src 'self'(?:;|\\s)/);
    assert.doesNotMatch(page, /script-src[^;]*unsafe-inline/i);
});

test('Secure Gallery markup contains no inline event handlers', () => {
    assert.doesNotMatch(page, /\\son[a-z]+\\s*=/i);
    assert.match(page, /data-sentryiq-nav="index\\.php\\?pane=view"/);
    assert.match(page, /data-sentryiq-nav="documents\\.php"/);
    assert.match(page, /data-sentryiq-nav="index\\.php\\?pane=settings"/);
    assert.match(navigation, /closest\\('\[data-sentryiq-nav\\]'\\)/);
});
