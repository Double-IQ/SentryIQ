(function () {
    'use strict';
    const button = document.getElementById('run');
    const output = document.getElementById('result');
    const csrf = document.querySelector('meta[name="csrf-token"]').content;
    function report(lines) { output.textContent = lines.join('\n'); }
    button.addEventListener('click', async function () {
        button.disabled = true;
        const lines = ['Preparing a short-lived, object-specific authorization…'];
        report(lines);
        let urls = null;
        let uploadMayExist = false;
        let passed = false;
        try {
            const preparedResponse = await fetch('gallery_b2_diagnostic.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {'Content-Type':'application/json','Accept':'application/json'},
                body: JSON.stringify({action:'prepare',csrf_token:csrf})
            });
            const prepared = await preparedResponse.json();
            if (!preparedResponse.ok || prepared.status !== 'ok') throw new Error(prepared.message || 'Could not prepare the B2 test.');
            urls = prepared;
            const bytes = new Uint8Array(32);
            crypto.getRandomValues(bytes);
            lines.push('PASS — PHP loaded the protected B2 configuration and signed short-lived URLs.');
            report(lines);
            const put = await fetch(urls.put, {
                method:'PUT', mode:'cors', credentials:'omit', cache:'no-store', redirect:'error',
                headers:{'Content-Type':urls.contentType}, body:bytes
            });
            if (!put.ok) throw new Error('B2 upload returned HTTP ' + put.status + '.');
            uploadMayExist = true;
            lines.push('PASS — browser uploaded a 32-byte random test object directly to B2.');
            report(lines);
            const get = await fetch(urls.get, {
                method:'GET', mode:'cors', credentials:'omit', cache:'no-store', redirect:'error'
            });
            if (!get.ok) throw new Error('B2 download returned HTTP ' + get.status + '.');
            const received = new Uint8Array(await get.arrayBuffer());
            if (received.length !== bytes.length || received.some((value, index) => value !== bytes[index])) {
                throw new Error('Downloaded test bytes did not match the uploaded bytes.');
            }
            lines.push('PASS — browser downloaded the object and verified every byte.');
            report(lines);
            passed = true;
        } catch (error) {
            lines.push('FAIL — ' + (error && error.message ? error.message : 'B2 test failed.'));
        } finally {
            if (urls && urls.delete && (uploadMayExist || !passed)) {
                try {
                    const deletion = await fetch(urls.delete, {
                        method:'DELETE', mode:'cors', credentials:'omit', cache:'no-store', redirect:'error'
                    });
                    if (deletion.ok || deletion.status === 404) {
                        lines.push('PASS — temporary test object deletion request completed.');
                    } else {
                        lines.push('WARNING — B2 did not confirm deletion (HTTP ' + deletion.status + '). Check the bucket for the temporary test object.');
                    }
                } catch (_) {
                    lines.push('WARNING — browser could not confirm deletion. Check the bucket for a temporary object under gallery/v1/.');
                }
            }
            if (passed) lines.push('RESULT — B2 upload, download and byte verification succeeded.');
            else lines.push('RESULT — test did not complete successfully. Do not upload personal photos yet.');
            report(lines);
            button.disabled = false;
        }
    });
}());
