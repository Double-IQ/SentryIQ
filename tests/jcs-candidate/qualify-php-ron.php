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
    '"\ud800"',
    '1e400',
    '{"unterminated":',
    '"\ufdd0"',
];
foreach ($invalidInputs as $input) {
    try {
        Ron::canonicalJson($input);
    } catch (Throwable) {
        continue;
    }
    throw new RuntimeException('php-ron accepted invalid I-JSON input: ' . $input);
}

echo "php-ron passed six RFC 8785 vectors and five strict-input rejection cases.\n";
