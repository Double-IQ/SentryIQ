<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/FulcioCertificateClaims.php';
require_once __DIR__ . '/../app/Updates/SnappyBlockDecoder.php';

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

// Regression fixture: the actual Fulcio leaf certificate from the v0.1.2
// GitHub Actions release run. This exercises the parser against a real cert,
// not only synthetic DER structures.
$releaseCertificate = base64_decode(preg_replace('/\s+/', '', <<<'CERT'
MIIG9jCCBnygAwIBAgIUPTWvdB1OtbKGfCqFLIz3uxRfQwgwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjYxMTA5MDUyNjMxWhcNMjYxMTA5MDUzNjMxWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEhNVFVpkuV8b7lCNhze9C4V+8GdTM0KW1Ld3C
GSh2zcmwpHqHPbFosCMeW00cfGYxDNAqrwCsy20ki9TEq2xJpaOCBZswggWXMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAWgBTf
0+nPViQRlvmo2OkoVaLGLhhkPzBiBgNVHREBAf8EWDBWhlRodHRwczovL2dpdGh1
Yi5jb20vRG91YmxlLUlRL1NlbnRyeUlRLy5naXRodWIvd29ya2Zsb3dzL3JlbGVh
c2UueW1sQHJlZnMvdGFncy92MC4xLjIwOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90
b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTASBgorBgEEAYO/MAEC
BARwdXNoMDYGCisGAQQBg78wAQMEKDljNjM5YTQ3OTJjYWRkNTQyMWYwMWVkMTk4
YmEyYTkyNjFjNTE0NWYwJAYKKwYBBAGDvzABBAQWQnVpbGQgU2VudHJ5UVEgUmVs
ZWFzZTAgBgorBgEEAYO/MAEFBBJEb3VibGUtSVEvU2VudHJ5UVEwHgYKKwYB
BAGDvzABBgQQcmVmcy90YWdzL3YwLjEuMjA7BgorBgEEAYO/MAEIBC0MK2h0dHBz
Oi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20wZAYKKwYBBAGD
vzABCQRWDFRodHRwczovL2dpdGh1Yi5jb20vRG91YmxlLUlRL1NlbnRyeUlRLy5naXRo
dWIvd29ya2Zsb3dzL3JlbGVhc2UueW1sQHJlZnMvdGFncy92MC4xLjIwOAYKKwYB
BAGDvzABCgQqDCg5YzYzOWE0NzkyY2FkZDU0MjFmMDFlZDE5OGJhMmE5MjYxYzUx
NDVmMB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDA1BgorBgEEAYO/MAEM
BCcMJWh0dHBzOi8vZ2l0aHViLmNvbS9Eb3VibGUtSVEvU2VudHJ5UVEwOAYKKwYB
BAGDvzABDQQqDCg5YzYzOWE0NzkyY2FkZDU0MjFmMDFlZDE5OGJhMmE5MjYxYzUx
NDVmMCAGCisGAQQBg78wAQ4EEgwQcmVmcy90YWdzL3YwLjEuMjAaBgorBgEEAYO/
MAEPBAwMCjEzNDU5NTYyMDYwLAYKKwYBBAGDvzABEAQeDBxodHRwczovL2dpdGh1
Yi5jb20vRG91YmxlLUlRMBkGCisGAQQBg78wAREECwwJMzAwMTQ0NjMwMGQGCisG
AQQBg78wARIEVgxUaHR0cHM6Ly9naXRodWIuY29tL0RvdWJsZS1JUS9TZW50cnlJ
US8uZ2l0aHViL3dvcmtmbG93cy9yZWxlYXNlLnltbEByZWZzL3RhZ3MvdjAuMS4y
MDgGCisGAQQBg78wARMEKgwoOWM2MzlhNDc5MmNhZGQ1NDIxZjAxZWQxOThiYTJh
OTI2MWM1MTQ1ZjAUBgorBgEEAYO/MAEUBAYMBHB1c2gwWQYKKwYBBAGDvzABFQRL
DElodHRwczovL2dpdGh1Yi5jb20vRG91YmxlLUlRL1NlbnRyeUlRL2FjdGlvbnMv
cnVucy80MjU2NzMyNDUzMi9hdHRlbXB0cy8xMBYGCisGAQQBg78wARYECAwGcHVi
bGljMFEGCisGAQQBg78wARgEQwxBcmVwbzpEb3VibGUtSVFAMzAwMTQ0NjMwL1Nl
bnRyeUlRQDEzNDU5NTYyMDY6cmVmOnJlZnMvdGFncy92MC4xLjIwgYsGCisGAQQB
1nkCBAIEfQR7AHkAdwDdPTBqxscRMmMZHhyZZzcCokpeuN48rf+HinKALynujgAA
AaG+xbnUAAAEAwBIMEYCIQD/Tkb2W/3++MyTrFMBPIlvnGdotHMErThnLu1Dw4ii
SwIhAOnt1uF9qL811zEmP7xQ5Bt0uK9thR54FZ3IQiZ4IpAVMAoGCCqGSM49BAMD
A2gAMGUCMFjE/S0bnCW2+BLacY8gG2rbzgCFCyylPUmN5Dgit/5+sBj9qbaxLQon
JOAiAox9XAIxAK+cCMeB/cXn4RlC6a6hd3bcXViJvkbgSPToAKYxx35MPC+hoN4n
AhISioscgVm3iQ==
CERT
), true);
if (!is_string($releaseCertificate)
    || FulcioCertificateClaims::workflowCommit($releaseCertificate) !== $sha) {
    throw new RuntimeException('Actual v0.1.2 Fulcio certificate Build Config Digest did not match.');
}

fulcioReject(fulcioCert(null), 'missing extension');
fulcioReject(fulcioCert(str_repeat('a', 39)), 'short SHA');
fulcioReject(fulcioCert('sha256:' . str_repeat('a', 64)), 'unsupported digest algorithm');
fulcioReject(fulcioCert($sha, false, true), 'duplicate extension');
fulcioReject(substr(fulcioCert($sha), 0, -1), 'truncated certificate');

function snappyReject(string $input, string $label): void {
    try { \SentryIQ\Updates\SnappyBlockDecoder::decode($input, 1024); }
    catch (Throwable) { return; }
    throw new RuntimeException('Expected Snappy rejection: ' . $label);
}
$snappy = \SentryIQ\Updates\SnappyBlockDecoder::class;
if ($snappy::decode("\x0b\x28hello world", 1024) !== 'hello world') {
    throw new RuntimeException('Snappy literal block did not decode.');
}
if ($snappy::decode("\x0c\x08abc\x22\x03\x00", 1024) !== 'abcabcabcabc') {
    throw new RuntimeException('Snappy overlapping two-byte copy did not decode.');
}
if ($snappy::decode("\x08\x0cabcd\x01\x04", 1024) !== 'abcdabcd') {
    throw new RuntimeException('Snappy one-byte copy did not decode.');
}
if ($snappy::decode("\x08\x0cabcd\x0f\x04\x00\x00\x00", 1024) !== 'abcdabcd') {
    throw new RuntimeException('Snappy four-byte copy did not decode.');
}
snappyReject("\x80\x00", 'overlong length varint');
snappyReject("\x05\x10abc", 'truncated literal');
snappyReject("\x04\x02\x01\x00", 'copy before output');
snappyReject("\x05\x28hello", 'declared output mismatch');
echo "Fulcio certificate claim tests passed.\n";
