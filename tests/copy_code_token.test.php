<?php

declare(strict_types=1);

function copyCodeCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function copyCodeRequest(string $url, string $method = 'GET', array $form = []): array
{
    $context = stream_context_create([
        'http' => [
            'method' => $method,
            'ignore_errors' => true,
            'timeout' => 4,
            'follow_location' => 0,
            'max_redirects' => 0,
            'header' => $method === 'POST' ? "Content-Type: application/x-www-form-urlencoded\r\n" : '',
            'content' => $method === 'POST' ? http_build_query($form) : '',
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

function copyCodeRemoveTree(string $path): void
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

$root = sys_get_temp_dir() . '/sentryiq-copy-code-' . bin2hex(random_bytes(8));
$public = $root . '/public';
$diagnostics = $public . '/diagnostics';
$private = $root . '/private';
foreach ([$diagnostics, $public . '/app/Security', $private] as $directory) {
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to prepare copy-code test workspace.');
    }
}

$server = null;
$pipes = [];
try {
    copy(dirname(__DIR__) . '/diagnostics/copy-code.php', $diagnostics . '/copy-code.php');
    copy(dirname(__DIR__) . '/security_bootstrap.php', $public . '/security_bootstrap.php');
    copy(dirname(__DIR__) . '/app/Security/SecurityBootstrap.php', $public . '/app/Security/SecurityBootstrap.php');
    file_put_contents(
        $public . '/sentryiq_config.php',
        '<?php return ' . var_export(['data_dir' => $private], true) . ';'
    );

    $router = $root . '/router.php';
    $routerCode = "<?php\n"
        . "\$_SERVER['HTTPS'] = 'on';\n"
        . "\$_SERVER['DOCUMENT_ROOT'] = " . var_export($public, true) . ";\n"
        . "\$path = parse_url(\$_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);\n"
        . "if (\$path !== '/diagnostics/copy-code.php') { http_response_code(404); exit; }\n"
        . "require " . var_export($diagnostics . '/copy-code.php', true) . ";\n";
    file_put_contents($router, $routerCode);

    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if ($socket === false) throw new RuntimeException('Unable to reserve copy-code test port: ' . $error);
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int)substr(strrchr((string)$address, ':'), 1);

    $server = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:' . $port, $router],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        $root
    );
    if (!is_resource($server)) throw new RuntimeException('Unable to start copy-code test server.');
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
    copyCodeCheck($ready, 'Copy-code test server did not start.');

    $token = bin2hex(random_bytes(32));
    $tokenFile = $private . '/token_' . $token . '.json';
    file_put_contents($tokenFile, json_encode(['code' => '123456', 'expires' => time() + 300], JSON_THROW_ON_ERROR));
    chmod($tokenFile, 0600);

    $url = 'http://127.0.0.1:' . $port . '/diagnostics/copy-code.php';
    [$getStatus, $getBody] = copyCodeRequest($url);
    copyCodeCheck($getStatus === 200, 'Copy-code page should load without a query token.');
    copyCodeCheck(!str_contains($getBody, $token) && !str_contains($getBody, '123456'), 'GET response must not disclose the token or verification code.');
    copyCodeCheck(is_file($tokenFile), 'GET must not consume the one-time token.');

    [$postStatus, $postBody] = copyCodeRequest($url, 'POST', ['t' => $token]);
    $payload = json_decode($postBody, true);
    copyCodeCheck($postStatus === 200 && ($payload['code'] ?? '') === '123456', 'POST must return the one-time code.');
    copyCodeCheck(!file_exists($tokenFile), 'A consumed token file must be removed.');
    $claimed = glob($private . '/consumed_*.token') ?: [];
    copyCodeCheck($claimed === [], 'Claimed token files must be removed after consumption.');

    [$replayStatus] = copyCodeRequest($url, 'POST', ['t' => $token]);
    copyCodeCheck($replayStatus === 404, 'A consumed token must not be replayable.');

    $expired = bin2hex(random_bytes(32));
    $expiredFile = $private . '/token_' . $expired . '.json';
    file_put_contents($expiredFile, json_encode(['code' => '654321', 'expires' => time() - 1], JSON_THROW_ON_ERROR));
    chmod($expiredFile, 0600);
    [$expiredStatus] = copyCodeRequest($url, 'POST', ['t' => $expired]);
    copyCodeCheck($expiredStatus === 410, 'Expired tokens must be rejected.');
    copyCodeCheck(!file_exists($expiredFile), 'Expired claimed token files must be removed.');

    echo "One-time copy-code POST and URL-fragment tests passed.\\n";
} finally {
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    foreach ($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
    copyCodeRemoveTree($root);
}
