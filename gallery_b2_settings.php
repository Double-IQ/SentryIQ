<?php
declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

require_once __DIR__ . '/cloud/Gallery/Storage/BackblazeB2Signer.php';

use SentryIQCloud\Gallery\Storage\BackblazeB2Signer;

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');

function gallery_b2_runtime_directory(): string
{
    $directory = sentryiq_data_dir();
    if ($directory === '' || !str_starts_with($directory, '/') || !is_dir($directory) || is_link($directory)) {
        throw new RuntimeException('SentryIQ protected storage is unavailable.');
    }
    $runtime = realpath($directory);
    $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
    if ($runtime === false || (is_string($documentRoot) && $documentRoot !== ''
        && ($runtime === $documentRoot || str_starts_with($runtime . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)))) {
        throw new RuntimeException('SentryIQ credentials storage must be outside the public web root.');
    }
    return rtrim($runtime, DIRECTORY_SEPARATOR);
}

function gallery_b2_write_configuration(string $runtime, array $configuration): void
{
    $target = $runtime . '/gallery_b2.php';
    if (is_link($target)) throw new RuntimeException('The existing Backblaze configuration path is unsafe.');
    $temporary = $runtime . '/.gallery_b2.php.tmp-' . bin2hex(random_bytes(12));
    $source = "<?php\ndeclare(strict_types=1);\nreturn " . var_export($configuration, true) . ";\n";
    $handle = @fopen($temporary, 'xb');
    if ($handle === false) throw new RuntimeException('SentryIQ could not create the protected configuration file.');
    try {
        if (!@chmod($temporary, 0600)) throw new RuntimeException('SentryIQ could not set secure configuration permissions.');
        $written = 0;
        $length = strlen($source);
        while ($written < $length) {
            $count = fwrite($handle, substr($source, $written));
            if ($count === false || $count === 0) throw new RuntimeException('SentryIQ could not write the protected configuration file.');
            $written += $count;
        }
        if (!fflush($handle)) throw new RuntimeException('SentryIQ could not flush the protected configuration file.');
        if (function_exists('fsync')) @fsync($handle);
    } catch (Throwable $exception) {
        fclose($handle);
        @unlink($temporary);
        throw $exception;
    }
    fclose($handle);
    if (!@rename($temporary, $target)) {
        @unlink($temporary);
        throw new RuntimeException('SentryIQ could not safely install the Backblaze configuration.');
    }
    @chmod($target, 0600);
    $permissions = @fileperms($target);
    if (!is_int($permissions) || (($permissions & 0077) !== 0)) {
        throw new RuntimeException('Backblaze configuration permissions are not owner-only.');
    }
}

$csrf = sentryiq_csrf_token();
$message = '';
$messageClass = 'success';
$runtime = '';
$configured = false;
$endpoint = '';

try {
    $runtime = gallery_b2_runtime_directory();
    try {
        $existing = BackblazeB2Signer::fromRuntimeDirectory($runtime);
        $configured = true;
        $endpoint = $existing->endpointHost();
    } catch (Throwable) {
        $configured = false;
    }
} catch (Throwable) {
    http_response_code(503);
    exit('SentryIQ protected storage is unavailable. Check the private runtime directory configuration.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        sentryiq_require_csrf();
        sentryiq_require_fresh_auth();
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'save') {
            $configuration = [
                'bucket' => strtolower(trim((string)($_POST['bucket'] ?? ''))),
                'region' => strtolower(trim((string)($_POST['region'] ?? ''))),
                'key_id' => trim((string)($_POST['key_id'] ?? '')),
                'application_key' => trim((string)($_POST['application_key'] ?? '')),
            ];
            if (strlen($configuration['bucket']) > 63 || strlen($configuration['region']) > 32
                || strlen($configuration['key_id']) > 256 || strlen($configuration['application_key']) > 512) {
                throw new RuntimeException('One or more Backblaze fields exceed the allowed length.');
            }
            // Validate all fields before touching the existing configuration.
            $candidate = new BackblazeB2Signer($configuration);
            gallery_b2_write_configuration($runtime, $configuration);
            $configured = true;
            $endpoint = $candidate->endpointHost();
            $message = 'Backblaze settings saved securely. Run the connection test before uploading any photos.';
            if (function_exists('log_security_event')) {
                log_security_event('GALLERY_B2_CONFIGURED', get_visitor_ip(), $_SESSION['app_username'] ?? 'unknown');
            }
        } elseif ($action === 'disconnect') {
            if ((string)($_POST['confirm_disconnect'] ?? '') !== 'yes') {
                throw new RuntimeException('Confirm that you understand disconnecting will pause Gallery storage.');
            }
            $target = $runtime . '/gallery_b2.php';
            if (is_link($target)) throw new RuntimeException('The existing Backblaze configuration path is unsafe.');
            if (is_file($target) && !@unlink($target)) throw new RuntimeException('SentryIQ could not remove the Backblaze configuration.');
            $configured = false;
            $endpoint = '';
            $message = 'Backblaze has been disconnected. Existing encrypted Gallery objects have not been deleted; reconnect the same bucket and key to access them again.';
            if (function_exists('log_security_event')) {
                log_security_event('GALLERY_B2_DISCONNECTED', get_visitor_ip(), $_SESSION['app_username'] ?? 'unknown');
            }
        } else {
            throw new RuntimeException('Unknown Backblaze settings operation.');
        }
    } catch (Throwable $exception) {
        $message = $exception->getMessage() !== '' ? $exception->getMessage() : 'Backblaze settings could not be saved.';
        $messageClass = 'error';
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<title>SentryIQ — Backblaze Storage</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<style>
.b2-settings{max-width:780px;margin:24px auto;padding:22px;border:1px solid #e3e6f0;border-radius:12px;background:#fff}
.b2-settings .field{margin:16px 0}
.b2-settings label{display:block;font-weight:600;margin-bottom:6px}
.b2-settings input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #cfd5df;border-radius:7px}
.b2-settings small{display:block;color:#687386;margin-top:5px}
.b2-status{padding:12px;border-radius:8px;background:#f2f5f8;margin:14px 0}
.b2-status.success{color:#176b3a}.b2-status.error{color:#a3212b}
.b2-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}
.b2-warning{font-size:14px;color:#6a4b00;background:#fff7df;padding:12px;border-radius:8px}
</style>
</head>
<body>
<div class="box">
  <div class="sentryiq-page-header">
    <div class="sentryiq-vault-brand-wrap">
      <img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ">
      <span class="sentryiq-vault-status">Backblaze Storage</span>
    </div>
    <div class="sentryiq-mobile-header-actions">
      <form method="POST" class="sentryiq-lock-form">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
        <input type="hidden" name="lock_vault" value="1">
        <button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button>
      </form>
    </div>
  </div>
  <div class="vault-tabs">
    <button class="tab-btn" type="button" onclick="window.location.href='index.php?pane=view'">📋 Vault</button>
    <button class="tab-btn" type="button" onclick="window.location.href='documents.php'">📄 Docs</button>
    <button class="tab-btn active" type="button" onclick="window.location.href='gallery.php'">🖼️ Gallery</button>
    <button class="tab-btn" type="button" onclick="window.location.href='index.php?pane=settings'">⚙️ System</button>
  </div>
  <main class="b2-settings">
    <h2>☁️ Backblaze B2 connection</h2>
    <p>Connect your private Backblaze bucket to SentryIQ Secure Gallery. Credentials stay on the server in the protected runtime directory; they are never saved in the database or sent back to this browser after submission.</p>
    <div class="b2-status <?php echo $configured ? 'success' : ''; ?>">
      <strong><?php echo $configured ? 'Configured' : 'Not connected'; ?></strong>
      <?php if ($configured): ?><div>Endpoint: <?php echo htmlspecialchars($endpoint, ENT_QUOTES, 'UTF-8'); ?></div><?php else: ?><div>Enter your bucket details below to configure storage.</div><?php endif; ?>
    </div>
    <?php if ($message !== ''): ?><p class="b2-status <?php echo htmlspecialchars($messageClass, ENT_QUOTES, 'UTF-8'); ?>" role="status"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></p><?php endif; ?>
    <div class="b2-warning">For security, saving or disconnecting requires a fresh vault unlock (within the last 5 minutes). The application key is never displayed again after saving. Do not paste credentials into chat or support messages.</div>
    <form method="POST" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
      <input type="hidden" name="action" value="save">
      <div class="field"><label for="bucket">Bucket name</label><input id="bucket" name="bucket" type="text" maxlength="63" required autocapitalize="none" spellcheck="false" placeholder="your-private-gallery-bucket"></div>
      <div class="field"><label for="region">B2 region</label><input id="region" name="region" type="text" maxlength="32" required autocapitalize="none" spellcheck="false" placeholder="e.g. us-west-004"><small>Use the region identifier shown in your Backblaze bucket details, not the full endpoint URL.</small></div>
      <div class="field"><label for="key_id">Application key ID</label><input id="key_id" name="key_id" type="password" maxlength="256" required autocomplete="new-password" spellcheck="false"></div>
      <div class="field"><label for="application_key">Application key</label><input id="application_key" name="application_key" type="password" maxlength="512" required autocomplete="new-password" spellcheck="false"></div>
      <div class="b2-actions"><button type="submit" class="btn btn-primary">Save Backblaze settings securely</button><a class="btn" href="gallery_b2_diagnostic.php">Run connection test</a><a class="btn" href="gallery.php">Return to Gallery</a></div>
    </form>
    <?php if ($configured): ?>
    <hr style="margin:24px 0;border:0;border-top:1px solid #e5e8ee">
    <h3>Disconnect Backblaze</h3>
    <p>Disconnecting removes the local credential file only. It does not delete encrypted objects from your bucket or erase Gallery metadata. Reconnect the same bucket and key to restore access.</p>
    <form method="POST" onsubmit="return confirm('Disconnect Backblaze? Gallery uploads and downloads will stop until you reconnect.');">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
      <input type="hidden" name="action" value="disconnect">
      <label style="display:flex;gap:8px;align-items:center;font-weight:400"><input style="width:auto" type="checkbox" name="confirm_disconnect" value="yes" required> I understand Gallery storage will be unavailable until reconnected.</label>
      <div class="b2-actions"><button type="submit" class="btn">Disconnect Backblaze</button></div>
    </form>
    <?php endif; ?>
  </main>
</div>
</body>
</html>
