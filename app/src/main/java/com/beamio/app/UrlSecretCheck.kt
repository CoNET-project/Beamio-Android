package com.beamio.app

/**
 * Spec r3dt §25.52BU.2 with r3dx §25.52BX.1 (PM R709/R713/R716): a page-supplied URL for openURL or openInAppBrowser
 * is checked before it is opened. A hit means: do not open, no event, answer
 * `{type:"ack", reqId, ok:false, error:"key_shaped_content"}` once, never echo the URL; logs carry only the rule number.
 *
 * Rules (each checked on the raw text and once percent-decoded):
 *  1. a parameter name in the query or fragment (case-insensitive, exact) from [KEY_NAMES]; a name starts after any `?`,
 *     `#`, `&` or `;` (also one inside a value) and runs to the next `=`, `&`, `;`, `#`, `?` or the end, so
 *     `?privateKey&`, `#privateKey`, `?a=x?privateKey=1` and `#a#privateKey` all hit, while a value
 *     (`?title=privateKey`) does not (spec r3et §25.52CT.2, union reading, fail closed; PM R781);
 *  2. `BEGIN PGP PRIVATE KEY` anywhere (case-sensitive);
 *  3. 12 or more consecutive English BIP-39 words separated by space, `+` or `%20`, anywhere;
 *  4. 64 or more consecutive hex characters (optional 0x, case-insensitive) in the query or fragment only; path segments
 *     are not checked (r3el §25.52CL.4 b: a 65-digit run hits);
 * Percent-decoding that fails (a `%` not followed by two hex digits, or bytes that are not UTF-8) is refused, fail closed
 * (PM R741, spec §25.52CK.5); it is logged as rule 5 (spec r3er §25.52CR.5, PM R770/R776/R781).
 *
 * The check is a backstop; the page must never put a credential in a URL (§25.52BM.1).
 */
object UrlSecretCheck {
    const val ERROR = "key_shaped_content"

    val KEY_NAMES: Set<String> = setOf(
        "privatekey", "privatekeyhex", "privatekeyarmor", "mnemonic", "mnemonicphrase", "recoverycode", "recoverywords",
        "pin", "passcode", "password", "passphrase", "pgppassphrase", "seed", "masterkey", "walletprivatekey",
    )

    private val HEX64 = Regex("(?i)(?:0x)?[0-9a-f]{64}")
    private const val PGP = "BEGIN PGP PRIVATE KEY"
    private val SEPARATORS = Regex("(?:%20|\\+|\\s)+", RegexOption.IGNORE_CASE)

    private val bip39: Set<String> by lazy {
        val stream = UrlSecretCheck::class.java.classLoader?.getResourceAsStream("bip39/english.txt")
        stream?.bufferedReader()?.useLines { lines -> lines.map { it.trim() }.filter { it.isNotEmpty() }.toSet() } ?: emptySet()
    }

    /** The rule number the URL hits (1 to 4, or 5 when percent-decoding fails), or null when it may be opened. */
    fun ruleFor(url: String): Int? {
        val decoded = percentDecodeOnce(url) ?: return DECODE_FAILED
        for (s in listOf(url, decoded)) {
            if (keyNameHit(queryAndFragment(s))) return 1
        }
        // Rule 2: raw and decoded, with spaces written as a space, "+" or "%20" (r3ek §25.52CK.5, CL.4).
        if (listOf(url, decoded, url.replace('+', ' '), decoded.replace('+', ' ')).any { it.contains(PGP) }) return 2
        if (bip39Run(url) || bip39Run(decoded)) return 3
        // Rule 4 (BX.1): query and fragment only, raw and decoded.
        val qf = queryAndFragment(url)
        val qfDecoded = percentDecodeOnce(qf) ?: return DECODE_FAILED
        if (HEX64.containsMatchIn(qf) || HEX64.containsMatchIn(qfDecoded)) return 4
        return null
    }

    /** Everything from the first `?` or `#` on; empty when the URL has neither. */
    internal fun queryAndFragment(url: String): String {
        val q = url.indexOf('?')
        val h = url.indexOf('#')
        val start = listOf(q, h).filter { it >= 0 }.minOrNull() ?: return ""
        return url.substring(start)
    }

    /** Parameter names (CT.2): after each `?`, `#`, `&` or `;`, including one inside a value, up to the next `=`, `&`, `;`, `#`, `?` or the end. */
    internal fun parameterNames(qf: String): List<String> {
        val names = ArrayList<String>()
        var i = 0
        while (i < qf.length) {
            if (qf[i] == '?' || qf[i] == '#' || qf[i] == '&' || qf[i] == ';') {
                var j = i + 1
                while (j < qf.length && qf[j] != '=' && qf[j] != '&' && qf[j] != ';' && qf[j] != '#' && qf[j] != '?') j++
                names += qf.substring(i + 1, j)
                // skip the value (if any) up to the next separator; a `?` inside a value starts a name too (CT.2)
                if (j < qf.length && qf[j] == '=') {
                    j++
                    while (j < qf.length && qf[j] != '&' && qf[j] != ';' && qf[j] != '#' && qf[j] != '?') j++
                }
                i = j
            } else i++
        }
        return names
    }

    private fun keyNameHit(qf: String): Boolean {
        if (qf.isEmpty()) return false
        return parameterNames(qf).any { it.trim().lowercase() in KEY_NAMES }
    }

    private fun bip39Run(s: String): Boolean {
        val words = bip39
        if (words.isEmpty()) return false
        var run = 0
        // Split on the allowed separators; any other character ends a run.
        for (token in SEPARATORS.split(s)) {
            val parts = token.split(Regex("[^A-Za-z]+"))
            if (parts.size == 1 && parts[0].lowercase() in words) {
                run += 1
                if (run >= 12) return true
            } else {
                // A token with other characters: its leading word may end a run and its trailing word may start one.
                val first = parts.firstOrNull()?.lowercase()
                if (first != null && first in words && run > 0) { run += 1; if (run >= 12) return true }
                val last = parts.lastOrNull()?.lowercase()
                run = if (last != null && last.isNotEmpty() && last in words && parts.size > 1) 1 else 0
            }
        }
        return false
    }

    const val DECODE_FAILED = 5

    /** One pass of percent-decoding (strict UTF-8); `+` stays as it is. Null when an escape is malformed or the bytes are not UTF-8. */
    internal fun percentDecodeOnce(s: String): String? {
        if (!s.contains('%')) return s
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length || !isHex(s[i + 1]) || !isHex(s[i + 2])) return null
                out.write((Character.digit(s[i + 1], 16) shl 4) or Character.digit(s[i + 2], 16))
                i += 3
            } else {
                out.write(c.toString().toByteArray(Charsets.UTF_8))
                i += 1
            }
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try { decoder.decode(java.nio.ByteBuffer.wrap(out.toByteArray())).toString() } catch (e: java.nio.charset.CharacterCodingException) { null }
    }

    private fun isHex(c: Char) = Character.digit(c, 16) >= 0
}
