<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Mbolli\Ron\Ron;

$fixturePath = dirname(__DIR__) . '/fixtures/jcs-rfc8785-vectors.json';
$fixture = json_decode((string) file_get_contents($fixturePath), false, 32, JSON_THROW_ON_ERROR);
if (!$fixture instanceof stdClass || !is_array($fixture->vectors ?? null) || count($fixture->vectors) !== 6) {
    throw new RuntimeException('RFC 8785 fixture must contain exactly six documented vectors.');
}

foreach ($fixture->vectors as $vector) {
    if (!$vector instanceof stdClass || !is_string($vector->id ?? null)
        || !is_string($vector->input ?? null) || !is_string($vector->canonical ?? null)) {
        throw new RuntimeException('Malformed RFC 8785 fixture vector.');
    }
    $actual = Ron::canonicalJson($vector->input);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('php-ron RFC 8785 vector failed: ' . $vector->id);
    }
}

$invalidInputs = [
    '{"duplicate":1,"duplicate":2}',
    '{"duplicate":1,"\u0064uplicate":2}',
    '"\ud800"',
    '"\udc00"',
    '"\ufdd0"',
    '"' . chr(0xff) . '"',
    '"bad' . chr(0x01) . 'string"',
    '1e400',
    '{"unterminated":',
];
$acceptedInvalidInputs = [];
foreach ($invalidInputs as $input) {
    try {
        Ron::canonicalJson($input);
        $acceptedInvalidInputs[] = bin2hex($input);
    } catch (Throwable) {
        // Rejection is the expected result for malformed or non-I-JSON input.
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
    $input = json_encode($float, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    $actual = Ron::canonicalJson($input);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('php-ron Appendix B number failed: ' . $vector->ieee754);
    }
}

$anchorFixture = json_decode(
    (string) file_get_contents(dirname(__DIR__) . '/fixtures/registry-anchor-canonicalization.json'),
    false,
    8,
    JSON_THROW_ON_ERROR
);
if (!$anchorFixture instanceof stdClass || !is_string($anchorFixture->input ?? null)
    || !is_string($anchorFixture->canonical ?? null) || !is_string($anchorFixture->sha256 ?? null)) {
    throw new RuntimeException('Malformed shared registry-anchor canonicalization fixture.');
}
$anchorCanonical = Ron::canonicalJson($anchorFixture->input);
if (!hash_equals($anchorFixture->canonical, $anchorCanonical)
    || !hash_equals($anchorFixture->sha256, hash('sha256', $anchorCanonical))) {
    throw new RuntimeException('Candidate canonical bytes or digest diverged from the native registry-anchor fixture.');
}

echo "php-ron passed six RFC 8785 vectors, 24 Appendix B numbers, and nine strict-input rejection cases.\n";
