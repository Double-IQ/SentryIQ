<?php

declare(strict_types=1);

function diagnosticWriteCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function diagnosticWriteRequest(string $url): array
{
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'ignore_errors' => true,
            'timeout' => 3,
            'follow_location' => 0,
            'max_redirects' => 0,
        ],
    ]);
    $body = @file_get_contents($url, false, $context);
    $status = 0;
    foreach (($http_response_header ?? []) as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $matches)) {
            $status = (int)$matches[1];
            break;
        }
    }
    return [$status, is_string($body) ? $body : ''];
}

function diagnosticWriteRemoveTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) rmdir($item->getPathname());
        else unlink($item->getPathname());
    }
    rmdir($path);
}

$root = sys_get_temp_dir() . '/sentryiq-diagnostic-write-' . bin2hex(random_bytes(8));
$public = $root . '/public/diagnostics';
if (!mkdir($public, 0700, true) && !is_dir($public)) {
    throw new RuntimeException('Unable to prepare diagnostic write test workspace.');
}

$server = null;
$pipes = [];
try {
    foreach (['post_install_write_diagnostic.php', 'vault_runtime_diagnostic.php'] as $file) {
        if (!copy(dirname(__DIR__) . '/diagnostics/' . $file, $public . '/' . $file)) {
            throw new RuntimeException('Unable to stage diagnostic write endpoint.');
        }
    }
    $router = $root . '/router.php';
    $routerCode = "<?php\n"
        . "\$target = basename((string)parse_url(\$_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH));\n"
        . "if (!in_array(\$target, ['post_install_write_diagnostic.php', 'vault_runtime_diagnostic.php'], true)) { http_response_code(404); exit; }\n"
        . "require __DIR__ . '/public/diagnostics/' . \$target;\n";
    file_put_contents($router, $routerCode);

    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if ($socket === false) throw new RuntimeException('Unable to reserve test port: ' . $error);
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int)substr(strrchr((string)$address, ':'), 1);

    $server = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:' . $port, $router],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        $root
    );
    if (!is_resource($server)) throw new RuntimeException('Unable to start diagnostic write test server.');
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

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
    diagnosticWriteCheck($ready, 'Diagnostic write test server did not start.');

    foreach (['post_install_write_diagnostic.php', 'vault_runtime_diagnostic.php'] as $file) {
        [$status, $body] = diagnosticWriteRequest('http://127.0.0.1:' . $port . '/diagnostics/' . $file);
        diagnosticWriteCheck($status === 404, $file . ' must be unavailable over HTTP; got ' . $status . '.');
        diagnosticWriteCheck(!str_contains($body, 'POST_INSTALL_WRITE_DIAGNOSTIC') && !str_contains($body, 'RUNTIME_GUARD_DIAGNOSTIC'), $file . ' disclosed diagnostic output over HTTP.');
    }

    echo "Write-capable diagnostics are CLI-only.\n";
} finally {
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    foreach ($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
    diagnosticWriteRemoveTree($root);
}
