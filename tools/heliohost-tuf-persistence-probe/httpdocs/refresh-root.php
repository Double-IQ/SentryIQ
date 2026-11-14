<?php

declare(strict_types=1);

register_shutdown_function(static function (): void {
    if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])) {
        $script = (string) $_SERVER['SCRIPT_FILENAME'];
        if ($script !== '' && is_file($script)) {
            @unlink($script);
        }
    }
});

require_once dirname(__DIR__) . '/sentryiq-tuf-patched-private/probe-common.php';
runSentryIqTufPersistenceProbe('refresh');
