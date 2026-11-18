<?php

declare(strict_types=1);

require_once __DIR__ . '/../cloud/Gallery/Storage/GalleryRotationStore.php';

use SentryIQCloud\Gallery\Storage\GalleryRotationStore;

function rotationJournalMustFail(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$directory = sys_get_temp_dir() . '/sentryiq-gallery-rotation-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) throw new RuntimeException('Unable to create Gallery rotation journal test directory.');

try {
    $journal = new GalleryRotationStore($directory . '/gallery_rotation.json');
    if ($journal->current() !== null) throw new RuntimeException('A new rotation journal must be empty.');

    $first = $journal->begin('gk_source01', 'gk_target01');
    if (($first['status'] ?? '') !== 'running') throw new RuntimeException('A new Gallery rotation must enter running state.');
    $same = $journal->begin('gk_source01', 'gk_target01');
    if (($same['id'] ?? '') !== $first['id']) throw new RuntimeException('Starting the same rotation must be idempotent.');

    rotationJournalMustFail(
        fn() => $journal->begin('gk_source01', 'gk_other001'),
        'A second concurrent rotation must be rejected.'
    );
    rotationJournalMustFail(
        fn() => $journal->begin('gk_source01', 'gk_source01'),
        'A rotation cannot target its source key.'
    );

    $aborted = $journal->abort($first['id']);
    if (($aborted['status'] ?? '') !== 'aborted') throw new RuntimeException('An active Gallery rotation should be abortable.');
    $second = $journal->begin('gk_source01', 'gk_target02');
    rotationJournalMustFail(
        fn() => $journal->complete($second['id'], ['complete' => false, 'references' => []]),
        'A rotation must reject an incomplete object inventory.'
    );
    rotationJournalMustFail(
        fn() => $journal->complete($second['id'], ['complete' => true, 'references' => ['gk_source01' => 1]]),
        'A rotation must not complete while any object or pending upload references its source key.'
    );
    $completed = $journal->complete($second['id'], ['complete' => true, 'references' => ['gk_target02' => 4]]);
    if (($completed['status'] ?? '') !== 'completed') throw new RuntimeException('A rotation with no source-key references should be markable complete.');
    if (($journal->current()['id'] ?? '') !== $second['id']) throw new RuntimeException('The latest Gallery rotation should remain durable.');

    $permissions = fileperms($directory . '/gallery_rotation.json');
    if (!is_int($permissions) || (($permissions & 0077) !== 0)) {
        throw new RuntimeException('Gallery rotation journal must be owner-only.');
    }

    echo "Gallery rotation journal tests passed.\n";
} finally {
    @unlink($directory . '/gallery_rotation.json');
    @unlink($directory . '/gallery_rotation.json.lock');
    @rmdir($directory);
}
