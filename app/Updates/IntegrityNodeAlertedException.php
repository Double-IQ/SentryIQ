<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/** Marks a node failure for which its direct owner alert was already delivered. */
final class IntegrityNodeAlertedException extends RuntimeException
{
}
