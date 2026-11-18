(function () {
    'use strict';
    document.addEventListener('click', function (event) {
        const button = event.target.closest('[data-sentryiq-nav]');
        if (!button) return;
        const target = button.getAttribute('data-sentryiq-nav');
        if (target) window.location.assign(target);
    });
    document.addEventListener('DOMContentLoaded', function () {
        const toggle = document.querySelector('.vault-mobile-menu-toggle');
        const menu = document.getElementById('vault-mobile-menu');
        if (toggle && menu) toggle.addEventListener('click', function () {
            const open = menu.classList.toggle('mobile-open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
    });
    document.addEventListener('submit', function (event) {
        const form = event.target.closest('form[data-confirm-submit]');
        if (!form) return;
        if (!window.confirm(form.getAttribute('data-confirm-submit') || 'Are you sure?')) event.preventDefault();
    });
}());
