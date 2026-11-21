'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

class EventTargetStub {
    constructor() { this.listeners = new Map(); }
    addEventListener(name, callback) {
        if (!this.listeners.has(name)) this.listeners.set(name, new Set());
        this.listeners.get(name).add(callback);
    }
    removeEventListener(name, callback) {
        if (this.listeners.has(name)) this.listeners.get(name).delete(callback);
    }
    dispatch(name) {
        for (const callback of this.listeners.get(name) || []) callback({ type: name });
    }
}

const documentStub = new EventTargetStub();
documentStub.visibilityState = 'visible';
const windowStub = new EventTargetStub();
windowStub.document = documentStub;
windowStub.setTimeout = setTimeout;
windowStub.clearTimeout = clearTimeout;
globalThis.window = windowStub;
require('../assets/js/gallery_session_guard.js');

const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

test('Gallery session guard resets the idle deadline after user activity', async () => {
    let reason = null;
    const guard = windowStub.SentryIQGallerySessionGuard.start(
        (value) => { reason = value; },
        { idleTimeoutMs: 35, hiddenTimeoutMs: 35 }
    );

    await wait(20);
    documentStub.dispatch('pointerdown');
    await wait(20);
    assert.equal(reason, null, 'recent activity should extend the idle deadline');
    await wait(25);
    assert.equal(reason, 'idle');
    guard.stop();
});

test('Gallery session guard locks after the page remains hidden', async () => {
    let reason = null;
    const guard = windowStub.SentryIQGallerySessionGuard.start(
        (value) => { reason = value; },
        { idleTimeoutMs: 100, hiddenTimeoutMs: 25 }
    );

    documentStub.visibilityState = 'hidden';
    documentStub.dispatch('visibilitychange');
    await wait(40);
    assert.equal(reason, 'background');
    guard.stop();
    documentStub.visibilityState = 'visible';
});

test('stopping the Gallery session guard cancels pending locks', async () => {
    let called = false;
    const guard = windowStub.SentryIQGallerySessionGuard.start(
        () => { called = true; },
        { idleTimeoutMs: 20, hiddenTimeoutMs: 20 }
    );
    guard.stop();
    await wait(35);
    assert.equal(called, false);
});

test('Gallery session guard locks immediately on pagehide so a restored page cannot retain an unlocked session', () => {
    let reason = null;
    windowStub.SentryIQGallerySessionGuard.start(
        (value) => { reason = value; },
        { idleTimeoutMs: 100, hiddenTimeoutMs: 100 }
    );

    windowStub.dispatch('pagehide');
    assert.equal(reason, 'pagehide');

    // The guard has detached its listeners and cancelled its pending timers.
    documentStub.dispatch('pointerdown');
    assert.equal(reason, 'pagehide');
});

test('Gallery session guard locks on return when a mobile browser suspended the background timer', () => {
    const originalSetTimeout = windowStub.setTimeout;
    const originalClearTimeout = windowStub.clearTimeout;
    const originalNow = Date.now;
    let now = 1000;
    let reason = null;

    // Simulate iOS suspending JavaScript timers while the page is hidden.
    windowStub.setTimeout = () => 1;
    windowStub.clearTimeout = () => {};
    Date.now = () => now;
    try {
        windowStub.SentryIQGallerySessionGuard.start(
            (value) => { reason = value; },
            { idleTimeoutMs: 1000, hiddenTimeoutMs: 60000 }
        );

        documentStub.visibilityState = 'hidden';
        documentStub.dispatch('visibilitychange');
        now += 60001; // The background timer never fires.
        documentStub.visibilityState = 'visible';
        documentStub.dispatch('visibilitychange');

        assert.equal(reason, 'background');
    } finally {
        windowStub.setTimeout = originalSetTimeout;
        windowStub.clearTimeout = originalClearTimeout;
        Date.now = originalNow;
        documentStub.visibilityState = 'visible';
    }
});
