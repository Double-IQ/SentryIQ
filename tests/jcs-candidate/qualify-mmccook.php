<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Mmccook\JsonCanonicalizator\JsonCanonicalizatorFactory;

$jcs = JsonCanonicalizatorFactory::getInstance();
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
    $value = json_decode($vector->input, false, 32, JSON_THROW_ON_ERROR);
    $actual = $jcs->canonicalize($value);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('RFC 8785 vector failed: ' . $vector->id);
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
    $actual = $jcs->canonicalize($float);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('Candidate JCS Appendix B number failed: ' . $vector->ieee754);
    }
}

echo "mmccook candidate passed six RFC 8785 vectors and 24 Appendix B numbers.\n";
echo "NOTE: candidate accepts decoded PHP values, not raw JSON; duplicate-member and strict UTF-8 parsing must be qualified separately.\n";
