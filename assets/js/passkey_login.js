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
    function showError(message) {
        var node = document.getElementById('passkey-status');
        node.textContent = message;
        node.style.display = 'block';
    }
    async function login() {
        if (!window.PublicKeyCredential || !navigator.credentials) { showError('Passkeys are not available in this browser.'); return; }
        var button = document.getElementById('passkey-login');
        button.disabled = true;
        try {
            var optionsResponse = await fetch('passkey_auth.php?action=login-options', { credentials: 'same-origin', cache: 'no-store' });
            var options = await optionsResponse.json();
            if (!optionsResponse.ok || options.status !== 'ok') throw new Error(options.message || 'Unable to start passkey authentication.');
            var publicKey = options.options;
            publicKey.challenge = b64urlToBytes(publicKey.challenge);
            if (publicKey.extensions && publicKey.extensions.prf && publicKey.extensions.prf.eval) publicKey.extensions.prf.eval.first = b64urlToBytes(publicKey.extensions.prf.eval.first);
            var credential = await navigator.credentials.get({ publicKey: publicKey });
            if (!credential) throw new Error('No passkey was returned.');
            var response = credential.response;
            var extensions = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
            var prf = extensions && extensions.prf && extensions.prf.results ? extensions.prf.results.first : null;
            if (!prf) throw new Error('This passkey does not provide the secure key needed to unlock this vault.');
            var resultResponse = await fetch('passkey_auth.php', { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify({
                action:'login', rawId:bytesToB64url(credential.rawId), clientDataJSON:bytesToB64url(response.clientDataJSON), authenticatorData:bytesToB64url(response.authenticatorData), signature:bytesToB64url(response.signature), prf:bytesToB64url(prf)
            }) });
            var result = await resultResponse.json();
            if (!resultResponse.ok || result.status !== 'ok') throw new Error(result.message || 'Passkey authentication failed.');
            window.location.href = 'welcome.php';
        } catch (error) {
            showError(error && error.message ? error.message : 'Passkey authentication was cancelled or failed.');
            button.disabled = false;
        }
    }
    document.getElementById('passkey-login').addEventListener('click', login);
}());
