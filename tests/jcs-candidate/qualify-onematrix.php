<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Tracing\Sdk\Canonicalize\JsonCanonicalizer;

$canonicalizer = new JsonCanonicalizer();
$fixture = json_decode((string) file_get_contents(dirname(__DIR__) . '/fixtures/jcs-rfc8785-vectors.json'), false, 32, JSON_THROW_ON_ERROR);
if (!$fixture instanceof stdClass || !is_array($fixture->vectors ?? null) || count($fixture->vectors) !== 6) {
    throw new RuntimeException('RFC 8785 fixture must contain exactly six documented vectors.');
}
foreach ($fixture->vectors as $vector) {
    $actual = $canonicalizer->canonicalize($vector->input);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('OneMatrix RFC 8785 vector failed: ' . $vector->id);
    }
}

$numberFixture = json_decode(
    (string) file_get_contents(dirname(__DIR__) . '/fixtures/jcs-rfc8785-appendix-b.json'),
    false,
    16,
    JSON_THROW_ON_ERROR
);
if (!$numberFixture instanceof stdClass || !is_array($numberFixture->vectors ?? null) || count($numberFixture->vectors) !== 24) {
    throw new RuntimeException('RFC 8785 Appendix B fixture must contain 24 finite number vectors.');
}
foreach ($numberFixture->vectors as $vector) {
    $bytes = hex2bin($vector->ieee754);
    if (!is_string($bytes) || strlen($bytes) !== 8) {
        throw new RuntimeException('Malformed Appendix B IEEE-754 value.');
    }
    $float = unpack('E', $bytes)[1];
    $rawNumber = json_encode($float, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    $actual = $canonicalizer->canonicalize($rawNumber);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('OneMatrix Appendix B number failed: ' . $vector->ieee754 . ' got ' . $actual);
    }
}

echo "OneMatrix canonicalizer passed six RFC 8785 vectors and 24 Appendix B numbers.\n";
echo "NOTE: duplicate-member rejection is enforced by SentryIQ's raw-input validator before canonicalization.\n";
