(function () {
    function b64urlToBytes(value) {
        var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        var raw = atob(base64), bytes = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        return bytes;
    }
    function bytesToB64url(buffer) {
        var bytes = new Uint8Array(buffer), binary = '';
        for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
    function derToPem(buffer) {
        var bytes = new Uint8Array(buffer), binary = '';
        for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        var base64 = btoa(binary);
        var lines = base64.match(/.{1,64}/g) || [];
        return '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') + '\n-----END PUBLIC KEY-----\n';
    }
    function showError(message) {
        var node = document.getElementById('passkey-status');
        node.textContent = message;
        node.style.display = 'block';
    }
    async function register() {
        if (!window.PublicKeyCredential || !navigator.credentials) { showError('Passkeys are not available in this browser.'); return; }
        var button = document.getElementById('passkey-register'); button.disabled = true;
        try {
            var optionsResponse = await fetch('passkey_auth.php?action=register-options', { credentials:'same-origin', cache:'no-store' });
            var options = await optionsResponse.json();
            if (!optionsResponse.ok || options.status !== 'ok') throw new Error(options.message || 'Unable to start passkey registration.');
            var publicKey = options.options;
            publicKey.challenge = b64urlToBytes(publicKey.challenge); publicKey.user.id = b64urlToBytes(publicKey.user.id);
            if (publicKey.extensions && publicKey.extensions.prf && publicKey.extensions.prf.eval) publicKey.extensions.prf.eval.first = b64urlToBytes(publicKey.extensions.prf.eval.first);
            var credential = await navigator.credentials.create({ publicKey:publicKey }); if (!credential) throw new Error('No passkey was created.');
            var response = credential.response; var extensions = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
            var prf = extensions && extensions.prf && extensions.prf.results ? extensions.prf.results.first : null;
            if (!prf) throw new Error('This device did not provide the secure passkey key material required by SentryIQ.');
            if (!response.getPublicKey) throw new Error('This browser cannot expose the passkey public key required by SentryIQ.');
            var publicKeyDer = response.getPublicKey(); if (!publicKeyDer) throw new Error('The passkey public key was unavailable.');
            var publicKeyPem = derToPem(publicKeyDer);
            var csrf = document.querySelector('meta[name="csrf-token"]').content;
            var resultResponse = await fetch('passkey_auth.php', { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify({
                action:'register', csrf_token:csrf, rawId:bytesToB64url(credential.rawId), clientDataJSON:bytesToB64url(response.clientDataJSON), authenticatorData:bytesToB64url(response.getAuthenticatorData ? response.getAuthenticatorData() : response.authenticatorData), publicKey:bytesToB64url(new TextEncoder().encode(publicKeyPem)), prf:bytesToB64url(prf)
            }) });
            var result = await resultResponse.json(); if (!resultResponse.ok || result.status !== 'ok') throw new Error(result.message || 'Passkey registration failed.');
            window.location.href = 'index.php';
        } catch (error) { showError(error && error.message ? error.message : 'Passkey registration was cancelled or failed.'); button.disabled = false; }
    }
    document.getElementById('passkey-register').addEventListener('click', register);
}());
