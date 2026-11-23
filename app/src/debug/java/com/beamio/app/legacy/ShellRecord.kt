package com.beamio.app.legacy

import java.io.File

/**
 * Plan N page record (spec r3ay §25.52D/§25.52E). The page keeps its record with the shell instead of PouchDB:
 * `shellRecordRead` / `shellRecordWrite` over an origin-limited channel. Pure logic here (unit-tested); the WebView
 * wiring is in [ShellRecordChannel].
 */
object ShellRecordRules {
    const val SCHEMA_VERSION = 1
    const val MAX_BYTES = 2 * 1024 * 1024

    /** §25.52D.8 forbidden paths (PGP private material). `[*]` stands for any array index. */
    val FORBIDDEN = setOf(
        "profiles[*].chatManager.pgpKey.privateKey", "profiles[*].chatManager.pgpKey.privateKeyArmor",
        "profiles[*].chatManager.pgpKey.privateKeyArmorWrap",
        "profiles[*].pgpKey.privateKey", "profiles[*].pgpKey.privateKeyArmor", "profiles[*].pgpKey.privateKeyArmorWrap",
        "pgpPassphrase", "profiles[*].chats[*].chatData.privateArmored",
    )

    /** §25.52D.8 W class (EOA private key and mnemonic): refused until a native copy is approved. */
    val WALLET = setOf("profiles[*].privateKeyArmor", "walletVault.mnemonic", "mnemonic")

    private val PROFILE_FIELDS = listOf(
        "isPrimary", "emailAddr", "hdPath", "index", "tokens", "isNode", "referrer", "spClub", "SpClubPoints", "spChannel",
        "airdropEvent", "data", "type", "nodeID", "nodeIP_address", "nodeRegion", "activePassport", "vpnTimeUsedInMin",
        "silentPassPassports", "webFilter", "chats", "phoneCalls", "aaAccount", "issuedCards", "keyID",
    )

    /** §25.52D.8 + §25.52E.3 whitelist (path prefixes). */
    val WHITELIST: List<String> = PROFILE_FIELDS.map { "profiles[*].$it" } + listOf(
        "profiles[*].chatManager.router", "profiles[*].chatManager.pgpKey.publicKey", "profiles[*].chatManager.pgpKey.keyID",
        "schemaVersion", "rev",
    )

    const val PRIVATE_HEADER = "BEGIN PGP PRIVATE KEY"

    sealed class Check {
        object Ok : Check()
        class Refuse(val code: String, val names: List<String>) : Check()
    }

    /** §25.52D.7 steps 4 to 8 for a parsed record (steps 1 to 3 belong to the transport). */
    internal fun checkRecord(record: CharJson.J, walletCopyApproved: Boolean): Check {
        val obj = record as? CharJson.J.Obj ?: return Check.Refuse("bad_request", listOf("record"))
        if ((obj.m["rev"] as? CharJson.J.Num)?.raw?.toLongOrNull() == null) return Check.Refuse("bad_request", listOf("rev"))
        if (containsHeader(record)) return Check.Refuse("pgp_private_in_payload", emptyList())
        val leaves = LinkedHashSet<String>()
        collect(record, "", leaves)
        val forbidden = leaves.filter { p -> FORBIDDEN.any { f -> p == f || p.startsWith("$f.") || p.startsWith("$f[") } }
        if (forbidden.isNotEmpty()) return Check.Refuse("pgp_private_in_payload", forbidden.map(::topMatch).distinct())
        if (!walletCopyApproved) {
            val w = leaves.filter { p -> WALLET.any { f -> p == f || p.startsWith("$f.") || p.startsWith("$f[") } }
            if (w.isNotEmpty()) return Check.Refuse("wallet_copy_not_approved", w.map { p -> WALLET.first { p == it || p.startsWith("$it.") || p.startsWith("$it[") } }.distinct())
        }
        val allowed = if (walletCopyApproved) WHITELIST + WALLET else WHITELIST
        val outside = leaves.filter { p -> allowed.none { a -> p == a || p.startsWith("$a.") || p.startsWith("$a[") } }
        if (outside.isNotEmpty()) return Check.Refuse("bad_request", outside.distinct())
        return Check.Ok
    }

    private fun topMatch(p: String) = FORBIDDEN.first { f -> p == f || p.startsWith("$f.") || p.startsWith("$f[") }

    /** Leaf paths (and empty containers) with `[*]` for array elements. */
    private fun collect(v: CharJson.J, path: String, out: MutableSet<String>) {
        when (v) {
            is CharJson.J.Obj -> if (v.m.isEmpty()) { if (path.isNotEmpty()) out += path } else for ((k, x) in v.m) collect(x, if (path.isEmpty()) k else "$path.$k", out)
            is CharJson.J.Arr -> if (v.a.isEmpty()) out += path else v.a.forEach { collect(it, "$path[*]", out) }
            else -> out += path
        }
    }

    internal fun containsHeader(v: CharJson.J): Boolean = when (v) {
        is CharJson.J.Obj -> v.m.values.any { containsHeader(it) }
        is CharJson.J.Arr -> v.a.any { containsHeader(it) }
        is CharJson.J.Str -> indexOf(v.c, PRIVATE_HEADER) >= 0
        else -> false
    }

    private fun indexOf(c: CharArray, needle: String): Int {
        outer@ for (i in 0..c.size - needle.length) {
            for (j in needle.indices) if (c[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /** Copy of [v] keeping only whitelisted paths (used to build the first page record from P). */
    internal fun filterToWhitelist(v: CharJson.J, path: String = "", walletCopyApproved: Boolean = false): CharJson.J? = when (v) {
        is CharJson.J.Obj -> {
            val m = LinkedHashMap<String, CharJson.J>()
            for ((k, x) in v.m) {
                val p = if (path.isEmpty()) k else "$path.$k"
                val list = if (walletCopyApproved) WHITELIST + WALLET else WHITELIST
                val allowedHere = list.any { a -> p == a || p.startsWith("$a.") || p.startsWith("$a[") }
                val onTheWay = list.any { a -> a.startsWith("$p.") || a.startsWith("$p[") }
                if (allowedHere) m[k] = x else if (onTheWay) filterToWhitelist(x, p, walletCopyApproved)?.let { m[k] = it }
            }
            CharJson.J.Obj(m)
        }
        is CharJson.J.Arr -> CharJson.J.Arr(ArrayList(v.a.mapNotNull { filterToWhitelist(it, "$path[*]", walletCopyApproved) }))
        else -> v
    }

    /** True when the old record carries W class data (non-empty mnemonic or a profile private key). */
    internal fun hasWalletData(root: CharJson.J): Boolean {
        val o = root as? CharJson.J.Obj ?: return false
        fun nonEmpty(x: CharJson.J?) = (x as? CharJson.J.Str)?.c?.isNotEmpty() == true
        if (nonEmpty(o.m["mnemonic"]) || nonEmpty(o.m["mnemonicPhrase"])) return true
        if (nonEmpty(((o.m["walletVault"] as? CharJson.J.Obj)?.m?.get("mnemonic")))) return true
        return ((o.m["profiles"] as? CharJson.J.Arr)?.a ?: emptyList()).any { nonEmpty((it as? CharJson.J.Obj)?.m?.get("privateKeyArmor")) }
    }
}

/** The native page record: one private file, whole-record replacement, atomic rename. Never logged. */
class ShellRecordStore(private val file: File, private val cipher: RecordCipher? = null) : LegacyPageStore {
    override fun hasRecord(): Boolean =
        try { read()?.also { it.json.fill('\u0000') } != null } catch (e: java.io.IOException) { true }

    override fun firstWrite(record: LegacyRecord, walletCopyApproved: Boolean): String? {
        if (ShellRecordRules.hasWalletData(record.tree()) && !walletCopyApproved) return "wallet_copy_not_approved"
        val page = ShellRecordRules.filterToWhitelist(record.tree(), walletCopyApproved = walletCopyApproved) as CharJson.J.Obj
        return if (write(page, 1)) null else "record_unreadable"
    }

    class Stored(val rev: Long, val json: CharArray)

    @Synchronized
    fun read(): Stored? {
        if (!file.isFile) return null
        val raw = file.readBytes()
        val bytes = cipher?.let { c -> try { c.open(raw) } finally { raw.fill(0) } } ?: raw
        val chars = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(bytes)).let { cb -> CharArray(cb.remaining()).also { cb.get(it) } }
        bytes.fill(0)
        val rev = try {
            ((CharJson.parse(chars) as? CharJson.J.Obj)?.m?.get("rev") as? CharJson.J.Num)?.raw?.toLong()
        } catch (e: CharJson.Bad) { null } ?: run { chars.fill('\u0000'); throw java.io.IOException("record_unreadable") }
        return Stored(rev, chars)
    }

    /** Writes [record] (already checked) with [newRev] set; returns false on failure (old file untouched). */
    @Synchronized
    internal fun write(record: CharJson.J.Obj, newRev: Long): Boolean = try {
        record.m["rev"] = CharJson.J.Num(newRev.toString())
        if (!record.m.containsKey("schemaVersion")) record.m["schemaVersion"] = CharJson.J.Num(ShellRecordRules.SCHEMA_VERSION.toString())
        val buf = CharJson.CharBuf(); CharJson.write(record, buf)
        val chars = buf.toArrayAndWipe()
        val bb = Charsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars)); chars.fill('\u0000')
        val out = ByteArray(bb.remaining()); bb.get(out)
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        val sealed = cipher?.let { c -> try { c.seal(out) } finally { out.fill(0) } } ?: out
        tmp.writeBytes(sealed); sealed.fill(0); out.fill(0)
        if (!tmp.renameTo(file)) { tmp.delete(); false } else true
    } catch (e: Exception) {
        false
    }
}
