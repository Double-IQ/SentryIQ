package co.bichet.sentryiq.master

import org.junit.Assert.*
import org.junit.Test

class ProtectedTrustStatePolicyTest {
    @Test fun acceptsFreshAnchorWithinOneDayWindow() {
        assertTrue(TrustRegistryAnchorPolicy.isFresh(1_700_000_000L, 1_700_086_400L, 1_700_000_100L))
    }

    @Test fun rejectsExpiredStaleAndOverlongAnchors() {
        assertFalse(TrustRegistryAnchorPolicy.isFresh(1_700_000_000L, 1_700_000_100L, 1_700_000_100L))
        assertFalse(TrustRegistryAnchorPolicy.isFresh(1_700_000_000L, 1_700_086_401L, 1_700_086_401L))
        assertFalse(TrustRegistryAnchorPolicy.isFresh(1_700_000_000L, 1_700_086_401L, 1_700_000_000L))
    }

    @Test fun allowsOnlySixtySecondsOfFutureClockSkew() {
        assertTrue(TrustRegistryAnchorPolicy.isFresh(1_700_000_060L, 1_700_000_300L, 1_700_000_000L))
        assertFalse(TrustRegistryAnchorPolicy.isFresh(1_700_000_061L, 1_700_000_300L, 1_700_000_000L))
    }
}
