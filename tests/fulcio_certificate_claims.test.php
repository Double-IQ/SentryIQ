<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/FulcioCertificateClaims.php';

use SentryIQ\Updates\FulcioCertificateClaims;

function fulcioDer(int $tag, string $value): string {
    $n = strlen($value);
    $length = $n < 128 ? chr($n) : "\x81" . chr($n);
    return chr($tag) . $length . $value;
}
function fulcioCert(?string $claim, bool $critical = false, bool $duplicate = false): string {
    $oid = hex2bin('060a2b0601040183bf300113');
    $extensions = '';
    if ($claim !== null) {
        $one = $oid . ($critical ? fulcioDer(0x01, "\xff") : '') . fulcioDer(0x04, fulcioDer(0x0c, $claim));
        $extensions .= fulcioDer(0x30, $one);
        if ($duplicate) $extensions .= fulcioDer(0x30, $one);
    }
    $tbs = fulcioDer(0x30, fulcioDer(0xa3, fulcioDer(0x30, $extensions)));
    return fulcioDer(0x30, $tbs . fulcioDer(0x30, '') . fulcioDer(0x03, "\x00"));
}
function fulcioReject(string $der, string $label): void {
    try { FulcioCertificateClaims::workflowCommit($der); }
    catch (Throwable) { return; }
    throw new RuntimeException('Expected rejection: ' . $label);
}
$sha = '9c639a4792cadd5421f01ed198ba2a9261c5145f';
if (FulcioCertificateClaims::workflowCommit(fulcioCert('sha1:' . $sha)) !== $sha) {
    throw new RuntimeException('Prefixed workflow digest was not normalized.');
}
if (FulcioCertificateClaims::workflowCommit(fulcioCert($sha, true)) !== $sha) {
    throw new RuntimeException('Critical extension encoding was not parsed.');
}
fulcioReject(fulcioCert(null), 'missing extension');
fulcioReject(fulcioCert(str_repeat('a', 39)), 'short SHA');
fulcioReject(fulcioCert('sha256:' . str_repeat('a', 64)), 'unsupported digest algorithm');
fulcioReject(fulcioCert($sha, false, true), 'duplicate extension');
fulcioReject(substr(fulcioCert($sha), 0, -1), 'truncated certificate');
echo "Fulcio certificate claim tests passed.\n";
