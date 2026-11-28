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
        assertNull(OwnerBootstrapHttpClient.extractSessionCookie("PHPSESSID=abcDEF0123456789_-\r", "PHPSESSID"))
    }

    @Test
    fun clearsOnlyTheConfiguredNativeCookie() {
        val jar = java.net.CookieManager()
        val endpoint = java.net.URI("https://sentryiq.example/api/owner-bootstrap.php")
        val session = java.net.HttpCookie("SID", "abcDEF0123456789_-").apply {
            path = "/"
            secure = true
            isHttpOnly = true
        }
        val unrelated = java.net.HttpCookie("theme", "dark").apply { path = "/" }
        jar.cookieStore.add(endpoint, session)
        jar.cookieStore.add(endpoint, unrelated)

        assertEquals(true, OwnerBootstrapHttpClient.clearNativeSessionCookie(
            java.net.URL("https://sentryiq.example"),
            "SID",
            jar
        ))
        assertNull(jar.cookieStore.get(endpoint).find { it.name == "SID" })
        assertEquals("dark", jar.cookieStore.get(endpoint).find { it.name == "theme" }?.value)
    }

    @Test
    fun invalidCookieNameDoesNotClearJar() {
        val jar = java.net.CookieManager()
        val endpoint = java.net.URI("https://sentryiq.example/api/owner-bootstrap.php")
        jar.cookieStore.add(endpoint, java.net.HttpCookie("SID", "abcDEF0123456789_-"))
        assertEquals(false, OwnerBootstrapHttpClient.clearNativeSessionCookie(
            java.net.URL("https://sentryiq.example"),
            "bad/name",
            jar
        ))
        assertEquals(1, jar.cookieStore.get(endpoint).size)
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
