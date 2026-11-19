document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.querySelector('.vault-mobile-menu-toggle');
    var menu = document.getElementById('vault-mobile-menu');

    if (toggle && menu) {
        toggle.addEventListener('click', function () {
            var open = menu.classList.toggle('mobile-open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
    }
});
