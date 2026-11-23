package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Spec §25.52BU.2 / §25.52BX.2 . Values below are synthetic: the BIP-39 phrase is the public all-zero test
 * vector ("abandon" x11 + "about"), the hex is a run of one repeated digit. No real key is used.
 */
class UrlSecretCheckTest {
    private val hex64 = "a".repeat(64)
    private val phrase = (List(11) { "abandon" } + "about")

    @Test
    fun normalHttpsLinkPasses() {
        assertNull(UrlSecretCheck.ruleFor("https://beamio.app/help?lang=en#top"))
        assertNull(UrlSecretCheck.ruleFor("https://example.com/path/to/page"))
    }

    @Test
    fun bx2HashesInThePathPass() {
        assertNull(UrlSecretCheck.ruleFor("https://explorer.example/tx/0x$hex64"))
        assertNull(UrlSecretCheck.ruleFor("https://explorer.example/block/0x$hex64"))
    }

    @Test
    fun bx2HexInQueryOrFragmentIsRefused() {
        assertEquals(4, UrlSecretCheck.ruleFor("https://any.example/p?x=0x$hex64"))
        assertEquals(4, UrlSecretCheck.ruleFor("https://any.example/p#$hex64"))
        assertEquals(4, UrlSecretCheck.ruleFor("https://any.example/p?x=${hex64}b")) // 65 digits hit (CL.4 b)
        assertNull(UrlSecretCheck.ruleFor("https://any.example/p?x=" + "a".repeat(63)))
        // percent-encoded in the query: decoded once, then checked
        val enc = hex64.chunked(1).joinToString("") { "%" + Integer.toHexString(it[0].code) }
        assertEquals(4, UrlSecretCheck.ruleFor("https://any.example/p?x=$enc"))
    }

    @Test
    fun rule1KeyNamesInQueryOrFragment() {
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p?privateKey=zz"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p?a=1&RecoveryCode=zz"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p#mnemonic=zz"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p?pass%77ord=zz")) // %77 = 'w'
        // r3el §25.52CL.4 a: the name alone counts, with or without "="
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p?privateKey&x=1"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p#privateKey"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p?a=1;seed"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://any.example/p?privateKey"))
        // r3et §25.52CT.2, union reading: a "?" inside a value and a second "#" start a name
        assertEquals(1, UrlSecretCheck.ruleFor("https://x/p?a=x?privateKey=1"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://x/p#a#privateKey"))
        assertEquals(1, UrlSecretCheck.ruleFor("https://x/p?a=1&privateKey"))
        assertNull(UrlSecretCheck.ruleFor("https://x/privateKey/p"))
        assertNull(UrlSecretCheck.ruleFor("https://x/p?privateKeys=1"))
        assertNull(UrlSecretCheck.ruleFor("https://x/p?title=privateKey"))
        // a fragment route: the parameter name is "/wallet/pin", not "pin" ("/" and "!" are not separators)
        assertNull(UrlSecretCheck.ruleFor("https://any.example/p#/wallet/pin=1234"))
        // a value is not a name; a key name only in the path is not rule 1
        assertNull(UrlSecretCheck.ruleFor("https://any.example/p?title=privateKey"))
        assertNull(UrlSecretCheck.ruleFor("https://any.example/password/reset"))
    }

    @Test
    fun rule2PgpPrivateHeader() {
        assertEquals(2, UrlSecretCheck.ruleFor("https://any.example/p?t=-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        assertEquals(2, UrlSecretCheck.ruleFor("https://any.example/p?t=-----BEGIN%20PGP%20PRIVATE%20KEY%20BLOCK-----"))
        assertEquals(2, UrlSecretCheck.ruleFor("https://any.example/p?t=-----BEGIN+PGP+PRIVATE+KEY+BLOCK-----")) // CK.5
    }

    @Test
    fun rule3TwelveBip39Words() {
        assertEquals(3, UrlSecretCheck.ruleFor("https://any.example/p?t=" + phrase.joinToString("+")))
        assertEquals(3, UrlSecretCheck.ruleFor("https://any.example/p?t=" + phrase.joinToString("%20")))
        assertEquals(3, UrlSecretCheck.ruleFor("https://any.example/" + phrase.joinToString(" ")))
        // eleven words are not a run of twelve
        assertNull(UrlSecretCheck.ruleFor("https://any.example/p?t=" + phrase.take(11).joinToString("+")))
    }

    /**: percent-decoding that fails is refused (fail closed); logged as rule 5 (r3er §25.52CR.5). */
    @Test
    fun badPercentEncodingIsRefused() {
        assertEquals(5, UrlSecretCheck.DECODE_FAILED)
        assertEquals(UrlSecretCheck.DECODE_FAILED, UrlSecretCheck.ruleFor("https://any.example/p?x=%zz"))
        assertEquals(UrlSecretCheck.DECODE_FAILED, UrlSecretCheck.ruleFor("https://any.example/p?x=abc%4"))
        assertEquals(UrlSecretCheck.DECODE_FAILED, UrlSecretCheck.ruleFor("https://any.example/p?x=%C3%28")) // not UTF-8
        assertNull(UrlSecretCheck.ruleFor("https://any.example/p?q=caf%C3%A9")) // valid UTF-8 passes
    }

    /** A refusal opens nothing and sends exactly one ack; the entry checks before it opens. */
    @Test
    fun entriesCheckBeforeOpening() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val open = Regex("fun openURL\\(url: String\\) \\{\\n([^\\n]*)\\n").find(src)
        checkNotNull(open)
        assertEquals("if (refuseKeyShapedUrl(url, null)) return", open.groupValues[1].trim())
        val inApp = Regex("private fun openInAppBrowserFromBridge\\(raw: String\\) \\{\\n[^\\n]*\\n([^\\n]*)\\n").find(src)
        checkNotNull(inApp)
        // Refusal comes before the URL is used to open anything (item 2).
        val body = Regex("private fun openInAppBrowserFromBridge\\(raw: String\\) \\{(.*?)\\n    \\}", RegexOption.DOT_MATCHES_ALL).find(src)!!.groupValues[1]
        val refuseAt = body.indexOf("if (refuseKeyShapedUrl(args.url, BridgeReqId.fromJsonText(raw))) return")
        val openAt = body.indexOf("sanitizedInAppBrowserUri(args.url)")
        assertTrue("refusal present", refuseAt >= 0)
        assertTrue("refusal before sanitize/open", openAt > refuseAt)
        // The ack carries the body's AW.1-checked reqId, never requestId.
        assertFalse(body.substring(0, openAt).contains("args.requestId"))
        val refuse = Regex("private fun refuseKeyShapedUrl\\(.*?\\n    \\}", RegexOption.DOT_MATCHES_ALL).find(src)!!.value
        assertEquals(1, Regex("dispatchAndroidBridgeJsonToWeb\\(").findAll(refuse).count())
        assertFalse("never echo the URL", Regex("put\\([^)]*url").containsMatchIn(refuse))
        assertTrue(refuse.contains("\"key_shaped_content\"") || refuse.contains("UrlSecretCheck.ERROR"))
    }
}
