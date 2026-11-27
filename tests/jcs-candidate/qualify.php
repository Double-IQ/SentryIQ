<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Accredify\\JsonCanonicalize\\JCS;

$fixturePath = dirname(__DIR__) . '/fixtures/jcs-rfc8785-vectors.json';
$fixture = json_decode((string) file_get_contents($fixturePath), false, 32, JSON_THROW_ON_ERROR);
if (!$fixture instanceof stdClass || !is_array($fixture->vectors ?? null) || count($fixture->vectors) !== 6) {
    throw new RuntimeException('RFC 8785 fixture must contain exactly six documented vectors.');
}

$jcs = new JCS();
foreach ($fixture->vectors as $vector) {
    if (!$vector instanceof stdClass || !is_string($vector->id ?? null)
        || !is_string($vector->input ?? null) || !is_string($vector->canonical ?? null)) {
        throw new RuntimeException('Malformed RFC 8785 fixture vector.');
    }
    $actual = $jcs->canonicalize($vector->input);
    if (!hash_equals($vector->canonical, $actual)) {
        throw new RuntimeException('RFC 8785 vector failed: ' . $vector->id);
    }
}

$invalidInputs = [
    '{"duplicate":1,"duplicate":2}',
    '"\\ud800"',
    '1e400',
    '{"unterminated":',
];
foreach ($invalidInputs as $input) {
    try {
        $jcs->canonicalize($input);
    } catch (Throwable) {
        continue;
    }
    throw new RuntimeException('Candidate accepted invalid I-JSON input: ' . $input);
}

echo "Candidate JCS passed six RFC 8785 vectors and four strict-input rejection cases.\\n";
