package co.bichet.sentryiq.master

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OwnerBootstrapSessionCookieTest {
    @Test
    fun copiesOnlyTheConfiguredSessionCookieValue() {
        assertEquals(
            "abcDEF0123456789_-",
            OwnerBootstrapHttpClient.extractSessionCookie("theme=dark; PHPSESSID=abcDEF0123456789_-; csrf=ignored", "PHPSESSID")
        )
    }

    @Test
    fun rejectsMissingAndDuplicateSessionCookies() {
        assertNull(OwnerBootstrapHttpClient.extractSessionCookie("theme=dark; csrf=ok", "PHPSESSID"))
        assertNull(
            OwnerBootstrapHttpClient.extractSessionCookie(
                "PHPSESSID=abcDEF0123456789_-; PHPSESSID=otherABCDEF0123456789_-",
                "PHPSESSID"
            )
        )
    }

    @Test
    fun rejectsUnsafeSessionCookieValues() {
        assertNull(OwnerBootstrapHttpClient.extractSessionCookie("PHPSESSID=short", "PHPSESSID"))
        assertNull(OwnerBootstrapHttpClient.extractSessionCookie("PHPSESSID=abc; injected=value", "PHPSESSID"))
        assertNull(OwnerBootstrapHttpClient.extractSessionCookie("PHPSESSID=abcDEF0123456789_-\n", "PHPSESSID"))
    }

    @Test
    fun acceptsOnlyStrictSessionCookieNames() {
        assertEquals("PHPSESSID", "PHPSESSID".takeIf { it.matches(Regex("^[A-Za-z0-9_-]{1,64}$")) })
        assertNull("bad/name".takeIf { it.matches(Regex("^[A-Za-z0-9_-]{1,64}$")) })
        assertNull("".takeIf { it.matches(Regex("^[A-Za-z0-9_-]{1,64}$")) })
    }

    @Test
    fun doesNotAcceptANameOtherThanTheConfiguredSessionCookie() {
        assertNull(OwnerBootstrapHttpClient.extractSessionCookie("PHPSESSID=abcDEF0123456789_-", "OTHER"))
    }
}
