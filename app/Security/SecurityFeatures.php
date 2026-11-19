<?php
require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" sizes="32x32" href="sentryiq-icon.php?size=32">
<link rel="icon" type="image/png" sizes="16x16" href="sentryiq-icon.php?size=16">
<link rel="apple-touch-icon" sizes="180x180" href="sentryiq-icon.php?size=180">
<meta property="og:site_name" content="SentryIQ">
<meta property="og:type" content="website">
<meta property="og:title" content="SentryIQ — Security">
<meta property="og:description" content="SentryIQ security architecture and controls.">
<meta property="og:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="1200">
<meta property="og:image:alt" content="SentryIQ">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="SentryIQ — Security">
<meta name="twitter:description" content="SentryIQ security architecture and controls.">
<meta name="twitter:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<title>SentryIQ — Security</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<link rel="stylesheet" href="assets/css/security_features.css">
</head>
<body>
<div class="box">
<h1>🔐 SentryIQ Security</h1>
<p>SentryIQ is designed as a defence-in-depth password vault. The security controls below describe the current release baseline.</p>
<div class="security-grid">
<section class="security-card"><h2>🔑 Master Password &amp; KDF</h2><ul><li>Master passwords are never stored in plaintext.</li><li>Vault keys are derived with Argon2id using a per-vault random salt.</li><li>The derived encryption key is exactly 32 bytes for AES-256-GCM.</li><li>KDF parameters are stored with the vault so the format is explicit and reproducible.</li></ul></section>
<section class="security-card"><h2>🛡️ Vault Encryption</h2><ul><li>AES-256-GCM authenticated encryption protects the complete vault.</li><li>Every save uses a fresh random 12-byte nonce.</li><li>The authentication tag is 16 bytes.</li><li>Vault metadata is cryptographically bound through GCM authenticated data.</li><li>The vault envelope is versioned for future secure format changes.</li></ul></section>
<section class="security-card"><h2>📁 Secure Storage</h2><ul><li>Vault data is intended to live outside the public web root.</li><li>The configured directory must be application-owned and not group/world accessible.</li><li>Vault, runtime and audit files use restrictive permissions.</li><li>Vault writes use a temporary file followed by an atomic rename.</li><li>Missing or invalid secure storage fails closed.</li></ul></section>
<section class="security-card"><h2>🔒 Authentication</h2><ul><li>Unlock requires the master password and a temporary email 2FA code.</li><li>2FA codes expire after 5 minutes.</li><li>Master-password failures are throttled server-side.</li><li>2FA verification failures are throttled and limited to five attempts.</li><li>Successful authentication regenerates the PHP session ID.</li></ul></section>
<section class="security-card"><h2>🍪 Session Protection</h2><ul><li>Secure, HttpOnly, SameSite=Strict session cookies.</li><li>PHP strict session mode is enabled.</li><li>Vault sessions have a 15-minute inactivity timeout.</li><li>Pending authentication material is cleared after success, expiry or lockout.</li><li>Locking the vault destroys the session.</li></ul></section>
<section class="security-card"><h2>🛡️ Request Protection</h2><ul><li>Every state-changing POST requires a session CSRF token.</li><li>Record edits and deletes enforce CSRF at the endpoint.</li><li>Security-sensitive settings require fresh authentication.</li><li>GET requests do not perform vault state changes.</li></ul></section>
<section class="security-card"><h2>🌐 Browser Security</h2><ul><li>Clickjacking protection and MIME-sniffing protection are enabled.</li><li>Referrer information is suppressed.</li><li>Vault pages are not cached.</li><li>External links opened in a new tab use noopener/noreferrer.</li><li>Stored resource URLs are HTTPS-only.</li></ul></section>
<section class="security-card"><h2>🌍 Icon Fetching</h2><ul><li>Stored resource URLs must use HTTPS.</li><li>Server-side icon requests require HTTPS.</li><li>Redirects are rejected rather than followed.</li><li>Downloaded content is validated as an allowed image type before storage.</li><li>Cached icons are stored outside the web root.</li></ul></section>
<section class="security-card"><h2>📧 2FA Copy Tokens</h2><ul><li>Copy tokens are cryptographically random.</li><li>The token URL never contains the 2FA code.</li><li>Tokens are stored outside the web root.</li><li>Token claiming is atomic, preventing concurrent replay.</li><li>The copy-code page is explicitly non-cacheable.</li></ul></section>
<section class="security-card"><h2>🚫 First Run</h2><ul><li>Installation is a one-time bootstrap operation.</li><li>The trusted application HTTPS URL is configured during installation and used for security-sensitive links.</li><li>The temporary bundled runtime files are copied to secure storage during setup.</li><li>The first-run script deletes itself after successful installation.</li><li>There is no public vault-reset path after installation.</li></ul></section>
<section class="security-card full"><h2>📝 Audit Logging</h2><p>Security events are recorded for authentication and vault state changes. The log does not store PHP session IDs or plaintext vault passwords.</p></section>
<section class="security-card full"><h2>⚠️ Security Boundary</h2><p>SentryIQ protects the vault within the application threat model. A compromised server, operating system, PHP runtime, browser session or configured 2FA email account remains outside the protection provided by vault encryption.</p></section>
</div>
</div>
</body>
</html>
