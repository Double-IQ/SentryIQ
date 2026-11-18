(function () {
    function getMenu(){return document.getElementById('vault-mobile-menu');}
    function getToggle(){return document.querySelector('.vault-mobile-menu-toggle');}
    window.toggleVaultMobileMenu=function(){var menu=getMenu(),toggle=getToggle();if(!menu||!toggle)return;var open=menu.classList.toggle('mobile-open');toggle.setAttribute('aria-expanded',open?'true':'false');};
    window.showAddCategoryForm=function(){var button=document.getElementById('show-add-category'),form=document.getElementById('add-category-form'),input=document.getElementById('new-category-name');if(!button||!form)return;button.style.display='none';form.style.display='flex';if(input)input.focus();};
    window.hideAddCategoryForm=function(){var button=document.getElementById('show-add-category'),form=document.getElementById('add-category-form'),input=document.getElementById('new-category-name');if(!button||!form)return;form.style.display='none';button.style.display='flex';if(input)input.value='';};
    window.showCreateFolderForm=function(){var button=document.querySelector('[data-vault-action="show-create-folder"]'),form=document.getElementById('create-folder-form'),input=document.getElementById('new-folder-name');if(!form)return;if(button)button.style.display='none';form.style.display='flex';if(input)input.focus();};
    window.hideCreateFolderForm=function(){var button=document.querySelector('[onclick="showCreateFolderForm()"]'),form=document.getElementById('create-folder-form'),input=document.getElementById('new-folder-name');if(!form)return;form.style.display='none';if(button)button.style.display='inline-block';if(input)input.value='';};
    function setupSystemOptions(){
        var panel=document.getElementById('settings-panel');
        if(!panel||panel.dataset.optionsReady==='1')return;
        var boxes=panel.querySelectorAll(':scope > .form-box');
        if(boxes.length<3)return;
        var params=new URLSearchParams(window.location.search);
        var application=params.get('tool')==='application';
        boxes[0].style.display=application?'block':'none';
        boxes[1].style.display='none';
        boxes[2].style.display='none';
        if(application){panel.dataset.optionsReady='1';return;}
        var options=document.createElement('div');options.className='form-box system-options-panel';options.style.marginTop='0';
        options.innerHTML='<h3>System Tools</h3>'+
            '<a href="gallery_settings.php" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>🖼️ Gallery Settings</strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">Control WebP quality, thumbnail quality, thumbnail size, and transparency handling.</span></a>'+
            '<a href="index.php?pane=settings&tool=application" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>⚙️ Application Settings</strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">Manage the application username, 2FA email, HTTPS URL, vault data directory, and IMAP settings.</span></a>'+
            '<a href="passkeys.php" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>🔑 Passkeys</strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">Manage the devices that can unlock your SentryIQ vault.</span></a>'+
            '<a href="system_log.php" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>🔐 System Log</strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">View security and authentication events recorded by SentryIQ.</span></a>'+
            '<a href="update.php" id="system-update-link" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>🔄 System Updates <span id="system-update-badge" style="display:none;margin-left:6px;padding:2px 7px;border-radius:999px;background:#fff3cd;color:#7a5a00;font-size:12px;font-weight:700;">Update available</span></strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">Check for and install stable SentryIQ releases without manually replacing application files.</span></a>'+
            '<a href="storage.php" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>💾 Storage</strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">View cPanel account quota, used space, available capacity, and SentryIQ folder sizes.</span></a>'+
            '<a href="security-features.php" class="system-option-link" style="display:block;padding:16px;margin-top:12px;border:1px solid #e9ecef;border-radius:10px;text-decoration:none;color:#212529;background:#fff;"><strong>🛡️ Security Details</strong><span style="display:block;margin-top:4px;color:#777;font-size:13px;">Explore the security controls built into SentryIQ, including encryption, passkeys, session protection, CSRF protection, secure storage, and audit logging.</span></a>';
        panel.appendChild(options);panel.dataset.optionsReady='1';
    }
    document.addEventListener('click', function (event) {
        const nav = event.target.closest('[data-sentryiq-nav]');
        if (nav) { const target = nav.getAttribute('data-sentryiq-nav'); if (target) window.location.assign(target); return; }
        const action = event.target.closest('[data-vault-action]');
        if (action && action.getAttribute('data-vault-action') === 'copy-secret') {
            if (typeof window.copyVaultString === 'function') window.copyVaultString(action, action.textContent);
            return;
        }
        if (action && action.getAttribute('data-vault-action') === 'return-to-list') {
            if (typeof window.returnToVaultList === 'function') window.returnToVaultList();
            return;
        }
        if (action && action.getAttribute('data-vault-action') === 'prepare-edit') {
            if (typeof window.prepareVaultEditNode === 'function') window.prepareVaultEditNode();
            return;
        }
        if (action) {
            const actions = {
                'show-add-category': window.showAddCategoryForm,
                'hide-add-category': window.hideAddCategoryForm,
                'show-create-folder': window.showCreateFolderForm,
                'hide-create-folder': window.hideCreateFolderForm
            };
            const handler = actions[action.getAttribute('data-vault-action')];
            if (typeof handler === 'function') handler();
            return;
        }
        const card = event.target.closest('.vault-record-card[data-vault-record]');
        if (card && (!event.target.closest('button') || event.target.closest('.inspect-button'))) {
            try { window.viewRecordDetails.apply(null, JSON.parse(card.getAttribute('data-vault-record'))); } catch (error) { console.error('Unable to open vault record.'); }
        }
    });
    document.addEventListener('submit', function (event) {
        const form = event.target.closest('form[data-confirm-submit]');
        if (form && !window.confirm(form.getAttribute('data-confirm-submit') || 'Are you sure?')) event.preventDefault();
    });
    document.addEventListener('keydown', function (event) {
        const card = event.target.closest('.vault-record-card[data-vault-record]');
        if (!card || (event.key !== 'Enter' && event.key !== ' ')) return;
        event.preventDefault();
        try { window.viewRecordDetails.apply(null, JSON.parse(card.getAttribute('data-vault-record'))); } catch (error) { console.error('Unable to open vault record.'); }
    });
    document.querySelectorAll('img[data-icon-fallback]').forEach(function (image) {
        image.addEventListener('error', function () {
            image.style.display = 'none';
            const fallback = image.nextElementSibling;
            if (fallback) fallback.style.display = 'inline-block';
        }, { once: true });
    });
    document.addEventListener('DOMContentLoaded',function(){var toggle=getToggle(),menu=getMenu();if(toggle&&menu){toggle.addEventListener('click',window.toggleVaultMobileMenu);menu.querySelectorAll('[data-vault-tab]').forEach(function(button){button.addEventListener('click',function(){var tab=button.getAttribute('data-vault-tab');if(typeof switchVaultTab==='function')switchVaultTab(tab);menu.classList.remove('mobile-open');toggle.setAttribute('aria-expanded','false');});});}setupSystemOptions();var badge=document.getElementById('system-update-badge');if(badge){fetch('update_check.php',{credentials:'same-origin',cache:'no-store',headers:{'Accept':'application/json'}}).then(function(response){return response.json();}).then(function(data){if(data&&data.status==='ok'&&data.update_available){badge.style.display='inline-block';}}).catch(function(){});}});
}());
