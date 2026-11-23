package com.beamio.app.legacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File

class LegacyPwaStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    // ---------- encoders for synthetic fixtures ----------

    private fun varint(o: ByteArrayOutputStream, v0: Long) { var v = v0; while (v >= 0x80) { o.write(((v and 0x7f) or 0x80).toInt()); v = v ushr 7 }; o.write(v.toInt()) }
    private fun bytes(f: (ByteArrayOutputStream) -> Unit) = ByteArrayOutputStream().also(f).toByteArray()
    private fun u16(o: ByteArrayOutputStream, s: String) { for (c in s) { o.write(c.code shr 8); o.write(c.code and 0xff) } }
    private fun le64(o: ByteArrayOutputStream, v: Long) { for (i in 0 until 8) o.write(((v ushr (8 * i)) and 0xff).toInt()) }
    private fun le32(o: ByteArrayOutputStream, v: Int) { for (i in 0 until 4) o.write((v ushr (8 * i)) and 0xff) }

    private fun snappyLiteral(raw: ByteArray) = bytes { o ->
        varint(o, raw.size.toLong())
        var i = 0
        while (i < raw.size) {
            val n = minOf(60, raw.size - i)
            o.write((n - 1) shl 2); o.write(raw, i, n); i += n
        }
    }

    private fun v8Str(o: ByteArrayOutputStream, s: String) { o.write('"'.code); varint(o, s.length.toLong()); o.write(s.toByteArray(Charsets.ISO_8859_1)) }
    private fun v8Obj(props: List<Pair<String, String>>) = bytes { o ->
        o.write(0xff); o.write(0x15); o.write(0xfe); repeat(12) { o.write(0) } // Blink header + trailer offset
        o.write(0xff); o.write(0x0f) // V8 version 15
        o.write('o'.code); for ((k, v) in props) { v8Str(o, k); v8Str(o, v) }; o.write('{'.code); varint(o, props.size.toLong())
    }
    private fun rowValue(v8: ByteArray, snappy: Boolean) = bytes { o ->
        o.write(if (snappy) 2 else 1)
        if (snappy) { o.write(0xff); o.write(0x11); o.write(0x02); o.write(snappyLiteral(v8)) } else o.write(v8)
    }

    private fun dbNameKey(name: String) = bytes { o -> o.write(byteArrayOf(0, 0, 0, 0, 0xC9.toByte())); varint(o, 6); u16(o, "origin"); varint(o, name.length.toLong()); u16(o, name) }
    private fun storeNameKey(db: Int, store: Int) = bytes { o -> o.write(byteArrayOf(0, db.toByte(), 0, 0, 50)); varint(o, store.toLong()); o.write(0) }
    private fun strKey(db: Int, store: Int, s: String) = bytes { o -> o.write(byteArrayOf(0, db.toByte(), store.toByte(), 1, 1)); varint(o, s.length.toLong()); u16(o, s) }
    private fun numKey(db: Int, store: Int, d: Double) = bytes { o -> o.write(byteArrayOf(0, db.toByte(), store.toByte(), 1, 3)); le64(o, java.lang.Double.doubleToLongBits(d)) }

    private class Op(val key: ByteArray, val value: ByteArray?)

    private fun batch(seq: Long, ops: List<Op>) = bytes { o ->
        le64(o, seq); le32(o, ops.size)
        for (op in ops) {
            o.write(if (op.value == null) 0 else 1); varint(o, op.key.size.toLong()); o.write(op.key)
            if (op.value != null) { varint(o, op.value.size.toLong()); o.write(op.value) }
        }
    }

    private fun logFile(records: List<ByteArray>) = bytes { o ->
        for (r in records) { o.write(byteArrayOf(0, 0, 0, 0)); o.write(r.size and 0xff); o.write(r.size shr 8); o.write(1); o.write(r) }
    }

    private fun manifest(logNumber: Long, tables: List<Long> = emptyList()) = logFile(listOf(bytes { o ->
        varint(o, 2); varint(o, logNumber)
        for (t in tables) { varint(o, 7); varint(o, 0); varint(o, t); varint(o, 100); varint(o, 1); o.write(0); varint(o, 1); o.write(0xff) }
    }))

    /** Uncompressed single-data-block table with internal keys. */
    private fun table(entries: List<Triple<ByteArray, Long, ByteArray?>>): ByteArray {
        fun block(kvs: List<Pair<ByteArray, ByteArray>>) = bytes { o ->
            for ((k, v) in kvs) { varint(o, 0); varint(o, k.size.toLong()); varint(o, v.size.toLong()); o.write(k); o.write(v) }
            le32(o, 0); le32(o, 1)
        }
        val data = block(entries.map { (k, seq, v) -> bytes { o -> o.write(k); le64(o, (seq shl 8) or (if (v == null) 0L else 1L)) } to (v ?: ByteArray(0)) })
        val out = ByteArrayOutputStream()
        out.write(data); out.write(0); le32(out, 0) // trailer: no compression, crc ignored
        val handle = bytes { o -> varint(o, 0); varint(o, data.size.toLong()) }
        val index = block(listOf(byteArrayOf(0x7f) to handle))
        val indexOff = out.size().toLong()
        out.write(index); out.write(0); le32(out, 0)
        val footer = bytes { o -> varint(o, 0); varint(o, 0); varint(o, indexOff); varint(o, index.size.toLong()) }
        out.write(footer); repeat(40 - footer.size) { out.write(0) }
        le64(out, -0x24b88adb747f04a9L)
        return out.toByteArray()
    }

    private val pgpPriv = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-TEST-ONLY\n-----END PGP PRIVATE KEY BLOCK-----"
    private val pgpPub = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB\n-----END PGP PUBLIC KEY BLOCK-----"

    private fun title(priv: String) = java.util.Base64.getEncoder().encodeToString(
        ("""{"mnemonicPhrase":"word word","profiles":[{"isPrimary":true,"keyID":"0xabc","privateKeyArmor":"0xeoa",""" +
            """"chatManager":{"pgpKey":{"keyID":"K1","privateKey":${json(priv)},"publicKey":${json(pgpPub)},"routes":""},"router":{}}}],"ver":1}""").toByteArray())

    private fun json(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

    private fun metaOps() = listOf(
        Op(dbNameKey("other-db"), byteArrayOf(2)),
        Op(dbNameKey("_pouch_conet"), byteArrayOf(1)),
        Op(storeNameKey(1, 1), bytes { u16(it, "document-store") }),
        Op(storeNameKey(1, 2), bytes { u16(it, "by-sequence") }),
        Op(storeNameKey(2, 1), bytes { u16(it, "document-store") }),
    )

    private fun docRow(rev: String, deleted: Boolean = false, snappy: Boolean = true) =
        rowValue(v8Obj(listOf("data" to "{}", "winningRev" to rev, "deletedOrLocal" to if (deleted) "1" else "0", "id" to "init")), snappy)

    private fun seqRow(rev: String, priv: String, snappy: Boolean = true) = rowValue(v8Obj(listOf("title" to title(priv), "_doc_id_rev" to "init::$rev")), snappy)

    private fun dir(log: ByteArray, manifest: ByteArray = manifest(3), tables: Map<Long, ByteArray> = emptyMap()): File {
        val d = tmp.newFolder()
        File(d, "CURRENT").writeText("MANIFEST-000001\n")
        File(d, "MANIFEST-000001").writeBytes(manifest)
        File(d, "000003.log").writeBytes(log)
        tables.forEach { (n, b) -> File(d, "%06d.ldb".format(n)).writeBytes(b) }
        return d
    }

    // ---------- tests ----------

    @Test
    fun readsWinningRevisionAndSplitsPgpFromThePageCopy() {
        val log = logFile(listOf(
            batch(1, metaOps()),
            batch(10, listOf(Op(numKey(1, 2, 1.0), seqRow("1-a", "OLD-REV-KEY")), Op(strKey(1, 1, "init"), docRow("1-a")))),
            batch(20, listOf(Op(numKey(1, 2, 2.0), seqRow("2-b", pgpPriv, snappy = false)), Op(strKey(1, 1, "init"), docRow("2-b")))),
            // same doc id in another database must be ignored
            batch(30, listOf(Op(strKey(2, 1, "init"), docRow("9-z")))),
        ))
        val r = LegacyPwaStore.read(dir(log))
        assertTrue(r.toString(), r is LegacyPwaStore.Result.Found)
        val rec = (r as LegacyPwaStore.Result.Found).record
        assertEquals("2-b", rec.winningRev)
        val keys = rec.pgpKeys()
        assertEquals(1, keys.size)
        assertEquals("chatManager.pgpKey", keys[0].layout)
        assertEquals(pgpPriv, String(keys[0].privateArmor))
        assertEquals(pgpPub, String(keys[0].publicArmor!!))
        val page = String(rec.pageCopyUtf8(), Charsets.UTF_8)
        assertFalse(page.contains("PRIVATE KEY"))
        assertFalse(page.contains("OLD-REV-KEY"))
        assertFalse("r3br: residual PGP public fields stripped", page.contains("\"publicKey\"") || page.contains("\"pgpKey\""))
        assertTrue(page.contains("\"router\"")) // chatManager.router stays
        assertTrue(page.contains("\"privateKeyArmor\":\"0xeoa\"")) // EOA stays with the page
        assertTrue(page.contains("\"mnemonicPhrase\""))
        val held = keys[0].privateArmor
        rec.wipe()
        assertTrue(held.all { it == '\u0000' })
    }

    @Test
    fun tableFilesAndLogDeletionsAreApplied() {
        val tbl = table(listOf(
            Triple(dbNameKey("_pouch_conet"), 1L, byteArrayOf(1)),
            Triple(storeNameKey(1, 1), 1L, bytes { u16(it, "document-store") }),
            Triple(storeNameKey(1, 2), 1L, bytes { u16(it, "by-sequence") }),
            Triple(strKey(1, 1, "init"), 5L, docRow("3-c")),
            Triple(numKey(1, 2, 3.0), 5L, seqRow("3-c", pgpPriv)),
        ))
        val ok = LegacyPwaStore.read(dir(logFile(emptyList()), manifest(3, listOf(7)), mapOf(7L to tbl)))
        assertTrue(ok is LegacyPwaStore.Result.Found)
        (ok as LegacyPwaStore.Result.Found).record.wipe()

        // a later deletion of the winning row in the log
        val gone = LegacyPwaStore.read(dir(logFile(listOf(batch(9, listOf(Op(numKey(1, 2, 3.0), null))))), manifest(3, listOf(7)), mapOf(7L to tbl)))
        assertTrue(gone is LegacyPwaStore.Result.Failed && gone.code == "winning_rev_missing")
    }

    @Test
    fun tablesNotInTheManifestAreIgnored() {
        val stale = table(listOf(Triple(dbNameKey("_pouch_conet"), 1L, byteArrayOf(1))))
        val r = LegacyPwaStore.read(dir(logFile(emptyList()), manifest(3), mapOf(5L to stale)))
        assertTrue(r is LegacyPwaStore.Result.NotFound)
    }

    @Test
    fun deletedDocumentAndMissingDatabaseAreNotFound() {
        val del = logFile(listOf(batch(1, metaOps()), batch(10, listOf(Op(strKey(1, 1, "init"), docRow("1-a", deleted = true)), Op(numKey(1, 2, 1.0), seqRow("1-a", pgpPriv))))))
        assertTrue(LegacyPwaStore.read(dir(del)) is LegacyPwaStore.Result.NotFound)
        assertTrue(LegacyPwaStore.read(dir(logFile(listOf(batch(1, listOf(Op(dbNameKey("x"), byteArrayOf(1)))))))) is LegacyPwaStore.Result.NotFound)
        assertTrue(LegacyPwaStore.read(File(tmp.root, "nope")) is LegacyPwaStore.Result.NotFound)
    }

    @Test
    fun unknownFormatsFailClosed() {
        val blob = bytes { o -> o.write(2); o.write(0xff); o.write(0x11); o.write(0x01); o.write(byteArrayOf(1, 2, 3)) }
        val log1 = logFile(listOf(batch(1, metaOps()), batch(10, listOf(Op(strKey(1, 1, "init"), blob)))))
        val r1 = LegacyPwaStore.read(dir(log1))
        assertTrue(r1 is LegacyPwaStore.Result.Failed && r1.code.startsWith("unsupported_format"))

        val weird = rowValue(bytes { o -> o.write(0xff); o.write(0x15); o.write(0xff); o.write(0x0f); o.write('?'.code) }, false)
        val log2 = logFile(listOf(batch(1, metaOps()), batch(10, listOf(Op(strKey(1, 1, "init"), weird)))))
        val r2 = LegacyPwaStore.read(dir(log2))
        assertTrue(r2 is LegacyPwaStore.Result.Failed && r2.code.startsWith("unsupported_format"))

        val d = tmp.newFolder(); File(d, "CURRENT").writeText("garbage")
        assertTrue(LegacyPwaStore.read(d).let { it is LegacyPwaStore.Result.Failed && it.code == "leveldb_corrupt" })
    }

    @Test
    fun snappyCopiesWork() {
        // "abcd" literal then copy(len 8, offset 4) → "abcdabcdabcd"
        val s = byteArrayOf(12, (3 shl 2).toByte(), 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 'd'.code.toByte(), ((8 - 1) shl 2 or 2).toByte(), 4, 0)
        assertEquals("abcdabcdabcd", String(Snappy.decompress(s)))
    }

    @Test
    fun pgpSecretPathsMatchThePageSanitizer() {
        for (m in listOf("privateKey", "privateKeyArmor", "privateKeyArmorWrap")) {
            assertTrue(m, LegacyRecord.isPgpSecret(listOf("profiles", "[]", "chatManager", "pgpKey"), m))
            assertTrue(m, LegacyRecord.isPgpSecret(listOf("profiles", "[]", "pgpKey"), m))
        }
        assertTrue(LegacyRecord.isPgpSecret(emptyList(), "pgpPassphrase"))
        assertFalse("EOA key stays", LegacyRecord.isPgpSecret(listOf("profiles", "[]"), "privateKeyArmor"))
        assertFalse(LegacyRecord.isPgpSecret(listOf("profiles", "[]", "chatManager", "pgpKey"), "publicKey"))
        assertFalse(LegacyRecord.isPgpSecret(listOf("profiles", "[]", "chatManager", "pgpKey"), "keyID"))
    }

    @Test
    fun bridgeCheckCountsPrivateFieldsAndArmorWithoutContent() {
        assertEquals(0, LegacyRecord.pgpPrivateHits("""{"profiles":[{"privateKeyArmor":"0xeoa","chatManager":{"pgpKey":{"publicKey":"pub"}}}]}""".toCharArray()))
        assertEquals(1, LegacyRecord.pgpPrivateHits("""{"profiles":[{"chatManager":{"pgpKey":{"privateKey":""}}}]}""".toCharArray()))
        assertEquals(1, LegacyRecord.pgpPrivateHits("""{"pgpPassphrase":"x"}""".toCharArray()))
        assertTrue(LegacyRecord.pgpPrivateHits("""{"note":"-----BEGIN PGP PRIVATE KEY BLOCK-----"}""".toCharArray()) >= 1)
        assertTrue("unparsable is refused", LegacyRecord.pgpPrivateHits("not json".toCharArray()) >= 1)
    }

    @Test
    fun pageCopyPassesTheBridgeCheck() {
        val log = logFile(listOf(batch(1, metaOps()), batch(20, listOf(Op(numKey(1, 2, 2.0), seqRow("2-b", pgpPriv)), Op(strKey(1, 1, "init"), docRow("2-b"))))))
        val rec = (LegacyPwaStore.read(dir(log)) as LegacyPwaStore.Result.Found).record
        val page = String(rec.pageCopyUtf8(), Charsets.UTF_8).toCharArray()
        assertEquals(0, LegacyRecord.pgpPrivateHits(page))
        rec.wipe()
    }

    /**
     * Real 0.52.932 data (team test account, kept outside the repo). Set BEAMIO_LEGACY_IDB_FIXTURE to the copied
     * `…indexeddb.leveldb` directory. Prints nothing but public facts.
     */
    @Test
    fun realFixtureWhenProvided() {
        val path = System.getenv("BEAMIO_LEGACY_IDB_FIXTURE")
        assumeTrue("fixture not provided", !path.isNullOrBlank())
        val r = LegacyPwaStore.read(File(path!!))
        assertTrue((r as? LegacyPwaStore.Result.Failed)?.code ?: "", r is LegacyPwaStore.Result.Found)
        val rec = (r as LegacyPwaStore.Result.Found).record
        val keys = rec.pgpKeys()
        assertEquals(1, keys.size)
        assertEquals("chatManager.pgpKey", keys[0].layout)
        assertTrue(String(keys[0].privateArmor).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        assertTrue(String(keys[0].publicArmor!!).startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        val page = String(rec.pageCopyUtf8(), Charsets.UTF_8)
        assertFalse(page.contains("PGP PRIVATE KEY"))
        // r3br: the listed residue is gone. chatManager.router (whitelisted) still carries route public armor by design.
        val tree = org.json.JSONObject(page)
        val cm = tree.getJSONArray("profiles").getJSONObject(0).getJSONObject("chatManager")
        assertEquals(listOf("router"), cm.keys().asSequence().toList())
        assertFalse(page.contains("pgpPublicKeyArmor") || page.contains("pgpPublicKeyID") || page.contains("\"pgpKey\""))
        println("real fixture: winningRev=${rec.winningRev.substringBefore('-')}-…, pgp keys=${keys.size}, page copy bytes=${page.length}")
        rec.wipe()
    }

    @Test
    fun r3brResiduePathsAreExact() {
        assertTrue(LegacyRecord.isPgpResidue(listOf("profiles", "[]", "chatManager"), "pgpKey"))
        assertTrue(LegacyRecord.isPgpResidue(listOf("profiles", "[]"), "pgpKey"))
        assertTrue(LegacyRecord.isPgpResidue(listOf("beamio"), "pgpPublicKeyArmor"))
        assertTrue(LegacyRecord.isPgpResidue(listOf("beamio"), "pgpPublicKeyID"))
        for (k in listOf("publicArmored", "routePgpKeyID", "routersArmoreds", "privateArmored"))
            assertTrue(k, LegacyRecord.isPgpResidue(listOf("profiles", "[]", "chats", "[]", "chatData"), k))
        assertFalse(LegacyRecord.isPgpResidue(listOf("profiles", "[]", "chatManager"), "router"))
        assertFalse(LegacyRecord.isPgpResidue(listOf("profiles", "[]"), "publicKeyArmor")) // EOA public key stays
        assertFalse(LegacyRecord.isPgpResidue(listOf("profiles", "[]", "chats", "[]", "chatData"), "online"))
    }
}
