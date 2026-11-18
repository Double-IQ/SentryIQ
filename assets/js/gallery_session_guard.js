(function (root) {
    'use strict';

    const DEFAULT_IDLE_TIMEOUT = 15 * 60 * 1000;
    const DEFAULT_HIDDEN_TIMEOUT = 60 * 1000;

    function timeoutValue(value, fallback) {
        return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
    }

    function start(onLock, options) {
        if (typeof onLock !== 'function') throw new TypeError('A Gallery lock callback is required.');
        const documentRef = root.document;
        if (!documentRef || typeof documentRef.addEventListener !== 'function'
            || typeof root.addEventListener !== 'function') {
            throw new Error('Gallery session protection is unavailable in this browser.');
        }

        const settings = options || {};
        const idleTimeout = timeoutValue(settings.idleTimeoutMs, DEFAULT_IDLE_TIMEOUT);
        const hiddenTimeout = timeoutValue(settings.hiddenTimeoutMs, DEFAULT_HIDDEN_TIMEOUT);
        let idleTimer = null;
        let hiddenTimer = null;
        let stopped = false;

        function clearTimers() {
            if (idleTimer !== null) root.clearTimeout(idleTimer);
            if (hiddenTimer !== null) root.clearTimeout(hiddenTimer);
            idleTimer = null;
            hiddenTimer = null;
        }

        function detach() {
            documentRef.removeEventListener('visibilitychange', handleVisibility);
            ['pointerdown', 'keydown', 'touchstart', 'click'].forEach(function (eventName) {
                documentRef.removeEventListener(eventName, handleActivity);
            });
            clearTimers();
        }

        function stop() {
            if (stopped) return;
            stopped = true;
            detach();
        }

        function lock(reason) {
            if (stopped) return;
            stopped = true;
            detach();
            onLock(reason);
        }

        function scheduleIdle() {
            if (stopped) return;
            if (idleTimer !== null) root.clearTimeout(idleTimer);
            idleTimer = null;
            if (documentRef.visibilityState === 'hidden') return;
            idleTimer = root.setTimeout(function () { lock('idle'); }, idleTimeout);
        }

        function handleActivity() {
            if (!stopped && documentRef.visibilityState !== 'hidden') scheduleIdle();
        }

        function handleVisibility() {
            if (stopped) return;
            if (documentRef.visibilityState === 'hidden') {
                if (idleTimer !== null) root.clearTimeout(idleTimer);
                idleTimer = null;
                if (hiddenTimer !== null) root.clearTimeout(hiddenTimer);
                hiddenTimer = root.setTimeout(function () { lock('background'); }, hiddenTimeout);
            } else {
                if (hiddenTimer !== null) root.clearTimeout(hiddenTimer);
                hiddenTimer = null;
                scheduleIdle();
            }
        }

        documentRef.addEventListener('visibilitychange', handleVisibility);
        ['pointerdown', 'keydown', 'touchstart', 'click'].forEach(function (eventName) {
            documentRef.addEventListener(eventName, handleActivity, { passive: true });
        });
        root.addEventListener('pagehide', function handlePageHide() {
            stop();
        }, { once: true });

        if (documentRef.visibilityState === 'hidden') handleVisibility();
        else scheduleIdle();

        return Object.freeze({ stop: stop, reset: scheduleIdle });
    }

    root.SentryIQGallerySessionGuard = Object.freeze({ start: start });
}(typeof window !== 'undefined' ? window : self));
