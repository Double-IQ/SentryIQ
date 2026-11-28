package co.bichet.sentryiq.master

import org.junit.Assert.assertEquals
import org.junit.Test

class MasterKeysetDigestTest {
    @Test fun matchesCrossPlatformGoldenVector() {
        val digest = MasterKeysetDigest.compute(
            "master-signing-abc", "ES256", ByteArray(64) { 0x01 },
            "master-key-agreement-def", "ECDH-ES", ByteArray(64) { 0x02 },
            "secure-enclave"
        )
        assertEquals("ff40c999ecdbeacc424f4c012a242a29cef1339f34b1692c9a1714518008e813", digest)
    }
}
