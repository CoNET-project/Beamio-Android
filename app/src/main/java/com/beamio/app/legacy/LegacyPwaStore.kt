package com.beamio.app.legacy

import java.io.File
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/**
 * Reads the old PWA wallet record (0.52.x, PouchDB idb adapter) straight from a copy of the WebView IndexedDB
 * directory, in native memory only (R349 plan N, source P per 25.52A.6). Never writes the directory.
 *
 * Path (measured on 0.52.932): database `_pouch_conet` → `document-store` row `init` (winningRev, deletedOrLocal)
 * → `by-sequence` row whose `_doc_id_rev` is `init::<winningRev>` → `title` = base64(JSON). PGP lives at
 * `profiles[i].chatManager.pgpKey.{privateKey, publicKey}` (older layouts: `profiles[i].pgpKey.{privateKeyArmor,
 * publicKeyArmor}`).
 *
 * The page never sees the PGP private key: [LegacyRecord.pageCopyUtf8] leaves it out. Secrets are kept in
 * CharArrays and [LegacyRecord.wipe] zeroes them. Unknown formats fail closed ([Result.Failed]); the old record is
 * then left untouched for a later retry.
 */
object LegacyPwaStore {
    const val DB_NAME = "_pouch_conet"
    const val DOC_STORE = "document-store"
    const val SEQ_STORE = "by-sequence"
    const val DOC_ID = "init"

    sealed class Result {
        class Found(val record: LegacyRecord) : Result()
        /** No old database, or no live `init` document. */
        object NotFound : Result()
        /** Present but unreadable. [code] is a short public reason, never data. */
        class Failed(val code: String) : Result()
    }

    fun read(leveldbDir: File): Result = try {
        readOrThrow(leveldbDir)
    } catch (e: LevelDbReader.Corrupt) {
        Result.Failed("leveldb_corrupt")
    } catch (e: Snappy.Corrupt) {
        Result.Failed("snappy_corrupt")
    } catch (e: IdbFormat.Unsupported) {
        // The message is a fixed reason from IdbFormat (format names, tag or version numbers), never stored data.
        Result.Failed("unsupported_format:" + (e.message ?: "").filter { it.isLetterOrDigit() || it == ' ' || it == '_' }.take(40))
    } catch (e: CharJson.Bad) {
        Result.Failed("json_invalid")
    } catch (e: IllegalArgumentException) {
        Result.Failed("base64_invalid")
    } catch (e: java.io.IOException) {
        Result.Failed("io_error")
    }

    private fun readOrThrow(dir: File): Result {
        if (!dir.isDirectory) return Result.NotFound
        val entries = LevelDbReader.readLive(dir)
        val dbId = entries.firstNotNullOfOrNull { IdbFormat.databaseName(it.key, it.value)?.takeIf { (n, _) -> n == DB_NAME }?.second }
            ?: return Result.NotFound
        val stores = entries.mapNotNull { IdbFormat.objectStoreName(it.key, it.value) }.filter { it.first == dbId }.associate { it.third to it.second }
        val docStore = stores[DOC_STORE] ?: return Result.Failed("no_document_store")
        val seqStore = stores[SEQ_STORE] ?: return Result.Failed("no_by_sequence")

        var winningRev: String? = null
        var deleted = false
        val bySeq = ArrayList<Pair<String, IdbFormat.V8.Str>>()
        for (e in entries) {
            val p = IdbFormat.prefix(e.key) ?: continue
            if (p.db != dbId || p.index != 1L) continue
            when (p.store) {
                docStore -> {
                    val k = IdbFormat.dataKey(e.key, p) as? IdbFormat.IdbKey.Str ?: continue
                    if (k.s != DOC_ID) continue
                    val obj = IdbFormat.parseV8(IdbFormat.unwrapValue(e.value)) as? IdbFormat.V8.Obj ?: throw IdbFormat.Unsupported("doc row")
                    winningRev = (obj.props["winningRev"] as? IdbFormat.V8.Str)?.text() ?: throw IdbFormat.Unsupported("winningRev")
                    deleted = (obj.props["deletedOrLocal"] as? IdbFormat.V8.Str)?.text()?.startsWith("1") == true
                    obj.props.values.forEach { (it as? IdbFormat.V8.Str)?.wipe() }
                }
                seqStore -> {
                    val obj = IdbFormat.parseV8(IdbFormat.unwrapValue(e.value)) as? IdbFormat.V8.Obj ?: continue
                    val rev = (obj.props["_doc_id_rev"] as? IdbFormat.V8.Str)?.text()
                    val title = obj.props["title"] as? IdbFormat.V8.Str
                    if (rev != null && rev.startsWith("$DOC_ID::") && title != null) bySeq += rev to title
                    obj.props.values.forEach { if (it !== title) (it as? IdbFormat.V8.Str)?.wipe() }
                }
            }
        }
        val rev = winningRev ?: run { bySeq.forEach { it.second.wipe() }; return Result.NotFound }
        if (deleted) { bySeq.forEach { it.second.wipe() }; return Result.NotFound }
        val hit = bySeq.firstOrNull { it.first == "$DOC_ID::$rev" }
        bySeq.forEach { if (it !== hit) it.second.wipe() }
        if (hit == null) return Result.Failed("winning_rev_missing")
        val title = hit.second
        try {
            val b64 = title.latin1 ?: String(title.chars!!).toByteArray(Charsets.ISO_8859_1)
            val json = java.util.Base64.getDecoder().decode(b64)
            val chars = utf8(json); json.fill(0)
            try {
                return Result.Found(LegacyRecord(rev, CharJson.parse(chars)))
            } finally {
                chars.fill('\u0000')
            }
        } finally {
            title.wipe()
        }
    }

    private fun utf8(b: ByteArray): CharArray {
        val dec = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        val cb: CharBuffer = try { dec.decode(ByteBuffer.wrap(b)) } catch (e: java.nio.charset.CharacterCodingException) { throw CharJson.Bad("utf8") }
        val out = CharArray(cb.remaining()); cb.get(out)
        cb.array().fill('\u0000')
        return out
    }
}

/** One old PGP key found in the record. Arrays belong to the record; [LegacyRecord.wipe] zeroes them. */
class LegacyPgp(val profileIndex: Int, val layout: String, val privateArmor: CharArray, val publicArmor: CharArray?)

class LegacyRecord internal constructor(val winningRev: String, private val root: CharJson.J) {
    private var wiped = false

    /** PGP keys in the record, primary profile first. */
    fun pgpKeys(): List<LegacyPgp> {
        check(!wiped)
        val profiles = ((root as? CharJson.J.Obj)?.m?.get("profiles") as? CharJson.J.Arr)?.a ?: return emptyList()
        val out = ArrayList<LegacyPgp>()
        profiles.forEachIndexed { i, p ->
            val po = p as? CharJson.J.Obj ?: return@forEachIndexed
            val cm = ((po.m["chatManager"] as? CharJson.J.Obj)?.m?.get("pgpKey") as? CharJson.J.Obj)?.m
            val cmPriv = (cm?.get("privateKey") as? CharJson.J.Str)?.c
            if (cmPriv != null && cmPriv.isNotEmpty()) out += LegacyPgp(i, "chatManager.pgpKey", cmPriv, (cm["publicKey"] as? CharJson.J.Str)?.c)
            val old = (po.m["pgpKey"] as? CharJson.J.Obj)?.m
            val oldPriv = (old?.get("privateKeyArmor") as? CharJson.J.Str)?.c
            if (oldPriv != null && oldPriv.isNotEmpty()) out += LegacyPgp(i, "pgpKey", oldPriv, (old["publicKeyArmor"] as? CharJson.J.Str)?.c)
        }
        return out.sortedByDescending { k -> ((profiles[k.profileIndex] as? CharJson.J.Obj)?.m?.get("isPrimary") as? CharJson.J.Bool)?.b == true }
    }

    /** `profiles[i].keyID` (public EOA address), or null. */
    fun profileKeyId(i: Int): String? {
        check(!wiped)
        val p = (((root as? CharJson.J.Obj)?.m?.get("profiles") as? CharJson.J.Arr)?.a?.getOrNull(i) as? CharJson.J.Obj) ?: return null
        return (p.m["keyID"] as? CharJson.J.Str)?.let { String(it.c) }
    }

    /** The parsed tree, for the page record initialisation (whitelist filter). Same lifetime as the record. */
    internal fun tree(): CharJson.J { check(!wiped); return root }

    /**
     * The record as UTF-8 JSON without any PGP private key (the page copy for the bridge). The caller wipes the
     * returned array after use. [extraSkip] lets the interface spec (r3au) drop further fields.
     */
    fun pageCopyUtf8(extraSkip: (List<String>, String) -> Boolean = { _, _ -> false }): ByteArray {
        check(!wiped)
        val buf = CharJson.CharBuf()
        CharJson.write(root, buf, emptyList()) { path, key -> isPgpSecret(path, key) || isPgpResidue(path, key) || extraSkip(path, key) }
        val chars = buf.toArrayAndWipe()
        val bb = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
        chars.fill('\u0000')
        val out = ByteArray(bb.remaining()); bb.get(out)
        if (bb.hasArray()) bb.array().fill(0)
        return out
    }

    fun wipe() {
        if (!wiped) { CharJson.wipe(root); wiped = true }
    }

    companion object {
        /**
         * Same field set as the page's `sanitizeForBridge` (plan N contract section 4): under `profiles[*].chatManager.pgpKey`
         * and `profiles[*].pgpKey` the members `privateKey`, `privateKeyArmor`, `privateKeyArmorWrap`; and top-level
         * `pgpPassphrase`. Public keys, keyIDs and the EOA fields stay.
         */
        val PGP_PRIVATE_MEMBERS = setOf("privateKey", "privateKeyArmor", "privateKeyArmorWrap")

        internal fun isPgpSecret(path: List<String>, key: String): Boolean {
            if (path.isEmpty() && key == "pgpPassphrase") return true
            if (key !in PGP_PRIVATE_MEMBERS) return false
            val underChatManager = path.size == 4 && path[0] == "profiles" && path[1] == "[]" && path[2] == "chatManager" && path[3] == "pgpKey"
            val underPgpKey = path.size == 3 && path[0] == "profiles" && path[1] == "[]" && path[2] == "pgpKey"
            return underChatManager || underPgpKey
        }

        /**
         * r3br §25.52V.3: residual PGP fields stripped from the page copy every time (first import and every read), besides the
         * private ones: the whole `profiles[*].chatManager.pgpKey` and `profiles[*].pgpKey`, `beamio.pgpPublicKeyArmor`,
         * `beamio.pgpPublicKeyID`, and in `profiles[*].chats[*].chatData` the `publicArmored`, `routePgpKeyID`, `routersArmoreds`
         * (and `privateArmored`).
         */
        internal fun isPgpResidue(path: List<String>, key: String): Boolean {
            val profile = path.size >= 2 && path[0] == "profiles" && path[1] == "[]"
            if (key == "pgpKey" && profile && (path.size == 2 || (path.size == 3 && path[2] == "chatManager"))) return true
            if (path == listOf("beamio") && (key == "pgpPublicKeyArmor" || key == "pgpPublicKeyID")) return true
            if (path.size == 5 && profile && path[2] == "chats" && path[3] == "[]" && path[4] == "chatData" &&
                key in setOf("publicArmored", "routePgpKeyID", "routersArmoreds", "privateArmored")) return true
            return false
        }

        /**
         * Bridge-exit and write-entry check: true when a JSON payload carries any PGP private field (same set) or a PGP
         * private key armor header anywhere. Returns only a count; never the content.
         */
        fun pgpPrivateHits(payload: CharArray): Int {
            var hits = 0
            val text = payload
            fun has(needle: String): Int {
                var n = 0; var i = 0
                outer@ while (i <= text.size - needle.length) {
                    for (j in needle.indices) if (text[i + j] != needle[j]) { i++; continue@outer }
                    n++; i += needle.length
                }
                return n
            }
            hits += has("PGP PRIVATE KEY BLOCK")
            val tree = try { CharJson.parse(payload) } catch (e: CharJson.Bad) { return hits + 1 } // unparsable payload is refused
            fun walk(v: CharJson.J, path: List<String>) {
                when (v) {
                    is CharJson.J.Obj -> for ((k, x) in v.m) { if (isPgpSecret(path, k)) hits++; walk(x, path + k) }
                    is CharJson.J.Arr -> v.a.forEach { walk(it, path + "[]") }
                    else -> Unit
                }
            }
            walk(tree, emptyList())
            CharJson.wipe(tree)
            return hits
        }
    }
}
