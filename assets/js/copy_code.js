(() => {
    const status = document.getElementById('status');
    const codeElement = document.getElementById('auth-code');
    const button = document.getElementById('copy-btn');
    const token = new URLSearchParams(location.hash.slice(1)).get('t') || '';
    history.replaceState(null, '', location.pathname);
    if (!/^[a-f0-9]{64}$/i.test(token)) {
        status.textContent = 'Verification token unavailable. Request a new sign-in code.';
        return;
    }
    fetch(location.pathname, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({t: token}).toString()
    }).then(async response => {
        const payload = await response.json();
        if (!response.ok || payload.status !== 'ok' || !/^\d{6}$/.test(payload.code || '')) {
            throw new Error(payload.message || 'Verification token unavailable.');
        }
        codeElement.textContent = payload.code;
        codeElement.hidden = false;
        button.hidden = false;
        status.textContent = 'Your one-time verification code is ready.';
    }).catch(error => {
        status.textContent = error instanceof Error ? error.message : 'Verification token unavailable.';
    });
    button.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(codeElement.textContent.trim());
            button.textContent = 'Code Copied';
        } catch (_) {
            status.textContent = 'Clipboard access was rejected by the browser.';
        }
    });
})();
