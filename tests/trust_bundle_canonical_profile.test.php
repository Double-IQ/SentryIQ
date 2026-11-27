<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/TrustBundleValidator.php';

use SentryIQ\Security\TrustBundleValidator;

$method = new ReflectionMethod(TrustBundleValidator::class, 'canonicalJson');
$method->setAccessible(true);
$validator = new TrustBundleValidator();

$assertCanonical = static function (mixed $value, string $expected) use ($method, $validator): void {
    $actual = $method->invoke($validator, $value);
    if ($actual !== $expected) {
        throw new RuntimeException('Restricted canonical profile produced unexpected bytes: ' . $actual);
    }
};

$rejectCanonical = static function (mixed $value, string $reason) use ($method, $validator): void {
    try {
        $method->invoke($validator, $value);
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($reason);
};

$ijsonMethod = new ReflectionMethod(TrustBundleValidator::class, 'assertIJsonValues');
$ijsonMethod->setAccessible(true);
$rejectIJson = static function (string $value, string $reason) use ($ijsonMethod, $validator): void {
    try { $ijsonMethod->invoke($validator, $value); }
    catch (Throwable) { return; }
    throw new RuntimeException($reason);
};
$rejectIJson("\\u{FDD0}", 'I-JSON noncharacters U+FDD0..U+FDEF must be rejected.');
$rejectIJson("\\u{1FFFF}", 'I-JSON plane-ending noncharacters must be rejected.');
$ijsonMethod->invoke($validator, "\\u{2028}\\u{2029}");

$assertCanonical(
    (object)['z' => 1, 'a' => (object)['true' => true, 'n' => null], 'slash' => 'a/b'],
    '{"a":{"n":null,"true":true},"slash":"a/b","z":1}'
);
$rejectCanonical(
    (object)["\u{10000}" => 1, 'a' => 2],
    'Non-ASCII object member names must be rejected by this restricted canonicalizer.'
);
$rejectCanonical(
    (object)['schema_version' => 1.0],
    'Floating-point numbers must not enter canonical trust-bundle payloads.'
);
$rejectCanonical(
    (object)['integer' => 9007199254740992],
    'Integers outside the interoperable JSON safe range must be rejected.'
);
$assertCanonical((object)['minimum' => -9007199254740991], '{"minimum":-9007199254740991}');

echo "Restricted canonical profile tests passed.\n";
