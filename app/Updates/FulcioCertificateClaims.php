<?php

declare(strict_types=1);

namespace SentryIQ\\Updates;

use RuntimeException;

/** Extracts the authenticated Fulcio Build Config Digest from a leaf certificate. */
final class FulcioCertificateClaims
{
    private const OID_WORKFLOW_SHA_DER = "\\x06\\x0a\\x2b\\x06\\x01\\x04\\x01\\x83\\xbf\\x30\\x01\\x13";

    public static function workflowCommit(string $certificateDer): string
    {
        if ($certificateDer === '' || strlen($certificateDer) > 1_000_000) {
            throw new RuntimeException('Fulcio leaf certificate is empty or exceeds the size limit.');
        }
        $outer = self::tlv($certificateDer, 0);
        if ($outer['tag'] !== 0x30 || $outer['end'] !== strlen($certificateDer)) {
            throw new RuntimeException('Fulcio leaf certificate is not one complete DER sequence.');
        }
        $certificateChildren = self::children($certificateDer, $outer['content'], $outer['end']);
        if (count($certificateChildren) !== 3 || $certificateChildren[0]['tag'] !== 0x30) {
            throw new RuntimeException('Fulcio leaf certificate structure is invalid.');
        }
        $tbs = $certificateChildren[0];
        $tbsChildren = self::children($certificateDer, $tbs['content'], $tbs['end']);
        $extensionContainers = [];
        foreach ($tbsChildren as $child) {
            if ($child['tag'] === 0xa3) $extensionContainers[] = $child;
        }
        if (count($extensionContainers) !== 1) {
            throw new RuntimeException('Fulcio certificate must contain exactly one extensions container.');
        }
        $wrapper = self::tlv($certificateDer, $extensionContainers[0]['content']);
        if ($wrapper['tag'] !== 0x30 || $wrapper['end'] !== $extensionContainers[0]['end']) {
            throw new RuntimeException('Fulcio certificate extensions container is malformed.');
        }
        $matches = [];
        foreach (self::children($certificateDer, $wrapper['content'], $wrapper['end']) as $extension) {
            if ($extension['tag'] !== 0x30) throw new RuntimeException('Fulcio certificate extension is malformed.');
            $fields = self::children($certificateDer, $extension['content'], $extension['end']);
            if (count($fields) < 2 || count($fields) > 3 || $fields[0]['tag'] !== 0x06) {
                throw new RuntimeException('Fulcio certificate extension fields are malformed.');
            }
            $oid = substr($certificateDer, $fields[0]['start'], $fields[0]['length']);
            if ($oid !== substr(self::OID_WORKFLOW_SHA_DER, 2)) continue;
            $valueField = $fields[1];
            if ($valueField['tag'] === 0x01 && count($fields) === 3) {
                if ($valueField['length'] !== 1
                    || substr($certificateDer, $valueField['content'], 1) !== "\\xff") {
                    throw new RuntimeException('Fulcio Build Config Digest critical flag is not canonical DER TRUE.');
                }
                $valueField = $fields[2];
            }
            if ($valueField['tag'] !== 0x04) {
                throw new RuntimeException('Fulcio Build Config Digest extension has an unexpected encoding.');
            }
            $value = self::tlv($certificateDer, $valueField['content']);
            if ($value['tag'] !== 0x0c || $value['end'] !== $valueField['end']) {
                throw new RuntimeException('Fulcio Build Config Digest must be a DER UTF8String.');
            }
            $matches[] = substr($certificateDer, $value['content'], $value['length']);
        }
        if (count($matches) !== 1) {
            throw new RuntimeException('Fulcio certificate must contain exactly one Build Config Digest extension.');
        }
        $claim = $matches[0];
        // GitHub workflow_sha may be encoded with its digest algorithm prefix.
        if (str_starts_with($claim, 'sha1:')) $claim = substr($claim, 5);
        if (preg_match('/^[a-fA-F0-9]{40}$/D', $claim) !== 1) {
            throw new RuntimeException('Fulcio Build Config Digest is not a supported full GitHub workflow SHA-1.');
        }
        return strtolower($claim);
    }

    /** @return array{tag:int,start:int,content:int,length:int,end:int} */
    private static function tlv(string $der, int $offset): array
    {
        $total = strlen($der);
        if ($offset < 0 || $offset + 2 > $total) throw new RuntimeException('Truncated DER value.');
        $tag = ord($der[$offset]);
        $first = ord($der[$offset + 1]);
        if (($tag & 0x1f) === 0x1f) throw new RuntimeException('High-tag-number DER values are unsupported.');
        $header = 2;
        if (($first & 0x80) === 0) $length = $first;
        else {
            $octets = $first & 0x7f;
            if ($octets === 0 || $octets > 4 || $offset + 2 + $octets > $total || ord($der[$offset + 2]) === 0) {
                throw new RuntimeException('Invalid or non-canonical DER length.');
            }
            $length = 0;
            for ($i = 0; $i < $octets; $i++) $length = ($length << 8) | ord($der[$offset + 2 + $i]);
            if ($length < 128) throw new RuntimeException('Non-canonical DER length.');
            $header += $octets;
        }
        $content = $offset + $header;
        $end = $content + $length;
        if ($end > $total || $end < $content) throw new RuntimeException('DER value exceeds its enclosing data.');
        return ['tag'=>$tag, 'start'=>$content, 'content'=>$content, 'length'=>$length, 'end'=>$end];
    }

    /** @return list<array{tag:int,start:int,content:int,length:int,end:int}> */
    private static function children(string $der, int $start, int $end): array
    {
        $items = [];
        while ($start < $end) {
            $item = self::tlv($der, $start);
            if ($item['end'] > $end) throw new RuntimeException('Nested DER value exceeds its parent.');
            $items[] = $item;
            $start = $item['end'];
        }
        if ($start !== $end) throw new RuntimeException('Malformed DER child sequence.');
        return $items;
    }
}
