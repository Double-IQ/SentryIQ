<?php

declare(strict_types=1);

/**
 * Integration tests for the post-install diagnostic access boundary.
 *
 * Uses PHP's built-in HTTP server with an isolated document root and session
 * directory. No production files or sessions are touched.
 */

function assertDiagnostic(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function removeDiagnosticTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) {
        @unlink($path);
        return;
    }

    foreach (scandir($path) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        removeDiagnosticTree($path . DIRECTORY_SEPARATOR . $entry);
    }
    @rmdir($path);
}

function diagnosticHttpRequest(string $url, ?string $cookie = null): array
{
    $headers = ["Connection: close"];
    if ($cookie !== null) {
        $headers[] = 'Cookie: ' . $cookie;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", $headers),
            'ignore_errors' => true,
            'timeout' => 3,
            'follow_location' => 0,
            'max_redirects' => 0,
        ],
    ]);

    $body = @file_get_contents($url, false, $context);
    $responseHeaders = $http_response_header ?? [];
    $status = 0;
    foreach ($responseHeaders as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $matches)) {
            $status = (int)$matches[1];
            break;
        }
    }

    return [$status, is_string($body) ? $body : '', $responseHeaders];
}

$repoRoot = dirname(__DIR__);
$temporaryRoot = sys_get_temp_dir() . '/sentryiq-diagnostic-test-' . bin2hex(random_bytes(8));
$documentRoot = $temporaryRoot . '/public';
$dataDirectory = $temporaryRoot . '/private-data';
$sessionDirectory = $temporaryRoot . '/sessions';

foreach ([$documentRoot . '/diagnostics', $documentRoot . '/app/Security', $dataDirectory, $sessionDirectory] as $directory) {
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create isolated diagnostic test directory.');
    }
}

$server = null;
$serverPipes = [];
try {
    if (!copy($repoRoot . '/diagnostics/post_install_diagnostic.php', $documentRoot . '/diagnostics/post_install_diagnostic.php')
        || !copy($repoRoot . '/app/Security/SecurityBootstrap.php', $documentRoot . '/app/Security/SecurityBootstrap.php')) {
        throw new RuntimeException('Unable to stage diagnostic endpoint test fixture.');
    }

    $configPath = $documentRoot . '/sentryiq_config.php';
    file_put_contents($configPath, '<?php return ' . var_export(['data_dir' => $dataDirectory], true) . ';');

    $routerPath = $temporaryRoot . '/router.php';
    file_put_contents(
        $routerPath,
        "<?php\n\$_SERVER['HTTPS'] = 'on';\nrequire __DIR__ . '/public/diagnostics/post_install_diagnostic.php';\n"
    );

    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if ($socket === false) {
        throw new RuntimeException('Unable to reserve a local test port: ' . $error);
    }
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int)substr(strrchr((string)$address, ':'), 1);

    $command = [
        PHP_BINARY,
        '-d',
        'session.save_path=' . $sessionDirectory,
        '-S',
        '127.0.0.1:' . $port,
        '-t',
        $documentRoot,
        $routerPath,
    ];
    $server = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $serverPipes, $temporaryRoot);

    if (!is_resource($server)) {
        throw new RuntimeException('Unable to start the isolated PHP test server.');
    }
    stream_set_blocking($serverPipes[1], false);
    stream_set_blocking($serverPipes[2], false);

    $url = 'http://127.0.0.1:' . $port . '/diagnostics/post_install_diagnostic.php';
    $ready = false;
    for ($attempt = 0; $attempt < 40; $attempt++) {
        $probe = @fsockopen('127.0.0.1', $port, $probeErrno, $probeError, 0.1);
        if (is_resource($probe)) {
            fclose($probe);
            $ready = true;
            break;
        }
        usleep(50000);
    }
    assertDiagnostic($ready, 'The isolated PHP test server did not become ready.');

    // Installed application + no authenticated session: redirect to login,
    // never return diagnostic JSON.
    [$status, $body] = diagnosticHttpRequest($url);
    assertDiagnostic($status === 302, 'Unauthenticated installed web request must redirect (HTTP 302); got ' . $status . '.');
    assertDiagnostic(!str_contains($body, 'POST_INSTALL_DIAGNOSTIC'), 'Unauthenticated web response disclosed diagnostic data.');

    // Installed application + authenticated vault session: diagnostic JSON.
    $sessionId = bin2hex(random_bytes(16));
    file_put_contents(
        $sessionDirectory . '/sess_' . $sessionId,
        'master_key|s:32:"' . str_repeat('K', 32) . '";'
    );
    [$status, $body] = diagnosticHttpRequest($url, 'PHPSESSID=' . $sessionId);
    assertDiagnostic($status === 200, 'Authenticated web request must succeed (HTTP 200); got ' . $status . '.');
    $record = json_decode($body, true);
    assertDiagnostic(is_array($record) && ($record['stage'] ?? '') === 'POST_INSTALL_DIAGNOSTIC', 'Authenticated web request must return the diagnostic JSON record.');

    // Missing installation config: web access must be hidden even if a session
    // cookie is supplied.
    unlink($configPath);
    [$status, $body] = diagnosticHttpRequest($url, 'PHPSESSID=' . $sessionId);
    assertDiagnostic($status === 404, 'Uninstalled web request must return HTTP 404; got ' . $status . '.');
    assertDiagnostic(!str_contains($body, 'POST_INSTALL_DIAGNOSTIC'), 'Uninstalled web response disclosed diagnostic data.');

    // CLI remains available without an installed config or web session.
    $cliRunner = $temporaryRoot . '/cli-diagnostic.php';
    file_put_contents(
        $cliRunner,
        "<?php\n\$_SERVER['REQUEST_METHOD'] = 'GET';\nrequire " . var_export($documentRoot . '/diagnostics/post_install_diagnostic.php', true) . ";\n"
    );
    $cliCommand = [
        PHP_BINARY,
        '-d',
        'session.save_path=' . $sessionDirectory,
        $cliRunner,
    ];
    $cliProcess = proc_open($cliCommand, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $cliPipes, $temporaryRoot);
    if (!is_resource($cliProcess)) {
        throw new RuntimeException('Unable to execute CLI diagnostic test.');
    }
    fclose($cliPipes[0]);
    $cliOutput = stream_get_contents($cliPipes[1]);
    $cliError = stream_get_contents($cliPipes[2]);
    fclose($cliPipes[1]);
    fclose($cliPipes[2]);
    $cliExit = proc_close($cliProcess);
    assertDiagnostic($cliExit === 0, 'CLI diagnostic must exit successfully; stderr: ' . $cliError);
    $cliRecord = json_decode((string)$cliOutput, true);
    assertDiagnostic(is_array($cliRecord) && ($cliRecord['stage'] ?? '') === 'POST_INSTALL_DIAGNOSTIC', 'CLI diagnostic must return its JSON record.');

    echo "Post-install diagnostic access tests passed (unauthenticated web, authenticated web, uninstalled web, CLI).\n";
} finally {
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    foreach ($serverPipes as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }
    removeDiagnosticTree($temporaryRoot);
}
