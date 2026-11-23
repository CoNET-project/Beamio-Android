package com.beamio.app.legacy

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/** Spec r3ay §25.52D/E: page bridge vectors TR-01..TR-13, source selection SR, startup init. */
class ShellRecordBridgeTest {
    @get:Rule val tmp = TemporaryFolder()

    private val vectorsText: String by lazy {
        val f = File("src/test/resources/plan-n/pgp-migration-vectors.v1.json")
        val sha = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("frozen r3ay vectors", "ba817cf7b9f718f9222024c721945b99412fafc20652a1c137d6af6453c27fbb", sha)
        f.readText()
    }

    private fun storeWith(stored: JSONObject?, writable: Boolean = true): ShellRecordStore {
        val dir = File(tmp.newFolder(), "rec").also { it.mkdirs() }
        val file = File(dir, "page-record.json")
        if (stored != null) {
            val rec = JSONObject(stored.getJSONObject("record").toString()).put("rev", stored.getLong("rev"))
            file.writeText(rec.toString())
        }
        if (!writable) dir.setWritable(false) // later writes fail; the existing file stays readable
        return ShellRecordStore(file)
    }

    private fun canon(v: Any?): String = when (v) {
        is JSONObject -> v.keys().asSequence().sorted().joinToString(",", "{", "}") { k -> "\"$k\":" + canon(v.get(k)) }
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canon(v.get(it)) }
        is String -> JSONObject.quote(v)
        is Number -> if (v.toDouble() == Math.floor(v.toDouble())) v.toLong().toString() else v.toString()
        else -> v.toString()
    }

    private fun readStore(s: ShellRecordStore): JSONObject? = s.read()?.let { JSONObject().put("rev", it.rev).put("record", JSONObject(String(it.json))) }

    @Test
    fun pageBridgeVectorsTr01ToTr13() {
        val cases = JSONObject(vectorsText).getJSONArray("shellRecordCases")
        assertEquals(13, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val ctx = c.getJSONObject("ctx")
            val expect = c.getJSONObject("expect")
            val stored = c.optJSONObject("store")
            val store = storeWith(stored, writable = !ctx.optBoolean("writeFailed"))
            val state = ShellRecordState().apply {
                migrating = ctx.optBoolean("migrating")
                initBlocked = if (ctx.optBoolean("initBlocked")) "wallet_copy_not_approved" else null
                walletCopyApproved = ctx.optBoolean("walletCopyApproved", false)
            }
            val logs = ArrayList<String>()
            val bridge = ShellRecordBridge(store, state) { logs += it }
            val req = c.optJSONObject("req") ?: JSONObject().put("reqId", "r-$id")
            val msg = JSONObject().put("type", if (c.getString("kind") == "read") "shellRecordRead" else "shellRecordWrite")
            if (req.has("reqId")) msg.put("reqId", req.get("reqId"))
            if (req.has("record")) msg.put("record", req.getJSONObject("record"))
            val text = msg.toString()
            val size = if (ctx.has("sizeBytes")) ctx.getInt("sizeBytes") else text.toByteArray().size
            val out = JSONObject(bridge.handle(ctx.optString("origin") == "allowed", text, size))

            assertEquals(id, expect.getString("code"), out.getString("code"))
            if (expect.has("reqId")) assertEquals(id, expect.get("reqId").toString(), out.get("reqId").toString())
            if (expect.has("sub")) assertEquals(id, expect.getString("sub"), out.getString("sub"))
            if (expect.has("currentRev")) assertEquals(id, expect.getLong("currentRev"), out.getLong("currentRev"))
            if (expect.has("rev")) assertEquals(id, expect.getLong("rev"), out.getLong("rev"))
            if (expect.has("names")) assertEquals(id, expect.getJSONArray("names").toString(), out.optJSONArray("names")?.toString() ?: "[]")
            if (expect.has("store")) {
                val want = expect.optJSONObject("store")
                val got = readStore(store)
                if (want == null) assertNull(id, got) else {
                    assertEquals(id, want.getLong("rev"), got!!.getLong("rev"))
                    assertEquals("$id record", canon(want.getJSONObject("record")), canon(got.getJSONObject("record")))
                }
            }
            // Logs carry codes and counts only, never values from the payload.
            logs.forEach { l -> assertFalse("$id log", l.contains("BEGIN PGP") || l.contains("EOA") || l.contains("PUB")) }
        }
    }

    @Test
    fun readReturnsRecordAndPassesTheExitAssertion() {
        val store = storeWith(JSONObject().put("rev", 2).put("record", JSONObject().put("schemaVersion", 1).put("profiles", JSONArray().put(JSONObject().put("emailAddr", "a")))))
        val logs = ArrayList<String>()
        val out = JSONObject(ShellRecordBridge(store, ShellRecordState()) { logs += it }.handle(true, """{"type":"shellRecordRead","reqId":7}""", 40))
        assertEquals("ok", out.getString("code"))
        assertEquals(2, out.getJSONObject("record").getInt("rev"))
        assertEquals(7, out.getInt("reqId"))
        assertTrue(logs.any { it.contains("exit assert pass") && it.contains("pgpPrivateHits=0") })
    }

    @Test
    fun exitAssertionBlocksAStoredPgpPrivateKey() {
        val bad = JSONObject().put("rev", 1).put("record", JSONObject().put("note", "-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        val logs = ArrayList<String>()
        val out = JSONObject(ShellRecordBridge(storeWith(bad), ShellRecordState()) { logs += it }.handle(true, """{"type":"shellRecordRead","reqId":"a"}""", 30))
        assertEquals("error", out.getString("code"))
        assertFalse(out.has("record"))
        assertTrue(logs.any { it.contains("exit assert FAIL") })
    }

    @Test
    fun fixedCommandSetAndReqIdRules() {
        val b = ShellRecordBridge(storeWith(null), ShellRecordState())
        fun call(m: String) = JSONObject(b.handle(true, m, m.length))
        call("""{"type":"shellRecordRead","reqId":"x","extra":1}""").let { assertEquals("bad_request", it.getString("code")); assertEquals("[\"extra\"]", it.getJSONArray("names").toString()) }
        call("""{"type":"shellRecordMigrationState","reqId":"x"}""").let { assertEquals("bad_request", it.getString("code")) }
        call("""{"type":"shellRecordRead","reqId":""}""").let { assertEquals("bad_request", it.getString("code")); assertTrue(it.isNull("reqId")) }
        call("""{"type":"shellRecordRead","reqId":9007199254740992}""").let { assertEquals("bad_request", it.getString("code")) }
        call("""{"type":"shellRecordRead","reqId":"${"a".repeat(65)}"}""").let { assertEquals("bad_request", it.getString("code")) }
        call("not json").let { assertEquals("bad_request", it.getString("code")) }
        call("""{"type":"shellRecordRead","reqId":"ok"}""").let { assertEquals("absent", it.getString("code")) }
    }

    // ---------- source selection (shell part of SR-04..SR-07) ----------

    private fun record(json: String): LegacyRecord {
        val r = LegacyRecord("1-a", CharJson.parse(json.toCharArray()))
        return r
    }

    private val eoa = "0x" + "ab".repeat(20)
    private val measured = """{"profiles":[{"isPrimary":true,"keyID":"${eoa.uppercase().replace("0X", "0x")}","privateKeyArmor":"e","chatManager":{"pgpKey":{"privateKey":"PRIV","publicKey":"PUB","keyID":"K"}}}]}"""

    @Test
    fun sourceSelection() {
        // SR-01/02: P readable, measured layout, account matches → use P
        val use = LegacySourceSelect.select(record(measured), null)
        assertTrue(use is LegacySourceSelect.Pick.UseP && use.eoa == eoa && String(use.pgp.privateArmor) == "PRIV")
        // SR-04: no record for the account
        val other = LegacySourceSelect.select(record(measured), "0x" + "cd".repeat(20))
        assertTrue(other is LegacySourceSelect.Pick.Refuse && other.code == "account_mismatch")
        // SR-05: only profiles[].pgpKey (layout not measured) → legacy_unreadable, P not used
        val old = LegacySourceSelect.select(record("""{"profiles":[{"keyID":"$eoa","pgpKey":{"privateKeyArmor":"P","publicKeyArmor":"Q"}}]}"""), null)
        assertTrue(old is LegacySourceSelect.Pick.Refuse && old.code == "legacy_unreadable")
        // SR-06/07: no P → the SDK reads L (or none)
        assertTrue(LegacySourceSelect.select(null, null) is LegacySourceSelect.Pick.NoP)
        assertTrue(LegacySourceSelect.select(record("""{"profiles":[{"keyID":"$eoa"}]}"""), null) is LegacySourceSelect.Pick.NoP)
    }

    // ---------- startup (§25.52D.9) ----------

    private class Recorder : PgpMigrationRunner {
        val calls = ArrayList<Triple<String, String?, Boolean>>()
        var heldPriv: ByteArray? = null
        override fun run(eoa: String, workspace: String, source: PgpMigrationRunner.Source?): String {
            calls += Triple(eoa, source?.let { String(it.privateArmor) }, source == null)
            heldPriv = source?.privateArmor
            source?.privateArmor?.fill(0); source?.publicArmor?.fill(0)
            return "ok"
        }
    }

    private fun idbDirFromFixture(): File? = System.getenv("BEAMIO_LEGACY_IDB_FIXTURE")?.let { File(it) }?.takeIf { it.isDirectory }

    @Test
    fun startupWithoutP() {
        val state = ShellRecordState()
        val store = storeWith(null)
        val runner = Recorder()
        val init = ShellRecordInit(File(tmp.root, "no-idb"), File(tmp.root, "copy"), store, state, runner)
        init.prepare()
        assertTrue(state.migrating)
        init.run()
        assertFalse(state.migrating)
        assertNull(state.initBlocked)
        assertNull(store.read())
        assertTrue(runner.calls.isEmpty()) // no P: the shell does not call with P; L is the SDK's own business ("no_p")
    }

    @Test
    fun startupWithRealPIsBlockedByWalletClassAndStillMigratesPgpFromP() {
        val p = idbDirFromFixture()
        org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val idb = tmp.newFolder("idb"); val dst = File(idb, p!!.name); p.copyRecursively(dst)
        val state = ShellRecordState()
        val store = storeWith(null)
        val runner = Recorder()
        val temp = File(tmp.root, "copy")
        val init = ShellRecordInit(dst, temp, store, state, runner)
        init.prepare()
        init.run()
        assertEquals("wallet_copy_not_approved", state.initBlocked) // W class present, not approved: no page record
        assertNull(store.read())
        assertEquals(1, runner.calls.size)
        assertTrue(runner.calls[0].second!!.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        assertTrue(runner.heldPriv!!.all { it == 0.toByte() })
        assertFalse(temp.exists()) // temp copy deleted
        assertTrue(dst.listFiles()!!.isNotEmpty()) // P itself untouched
        // page read now answers error + wallet_copy_not_approved, never absent
        val out = JSONObject(ShellRecordBridge(store, state).handle(true, """{"type":"shellRecordRead","reqId":"r"}""", 40))
        assertEquals("error", out.getString("code")); assertEquals("wallet_copy_not_approved", out.getString("sub"))
    }

    @Test
    fun startupSkipsPOnceThePageHasItsRecord() {
        val state = ShellRecordState()
        val store = storeWith(JSONObject().put("rev", 3).put("record", JSONObject().put("schemaVersion", 1)))
        val idb = tmp.newFolder("idb2"); File(idb, "CURRENT").writeText("MANIFEST-000001")
        val temp = File(tmp.root, "copy2")
        val init = ShellRecordInit(idb, temp, store, state, Recorder())
        init.prepare()
        assertFalse(temp.exists()) // P not copied
        init.run()
        assertEquals(3, store.read()!!.rev)
    }

    @Test
    fun whitelistFilterAndWalletDetection() {
        val tree = CharJson.parse("""{"mnemonicPhrase":"m","beamio":{"x":1},"profiles":[{"keyID":"k","privateKeyArmor":"e","tokens":{"a":1},"chatManager":{"router":{},"pgpKey":{"privateKey":"P","publicKey":"Q","keyID":"K","routes":""}}}]}""".toCharArray())
        assertTrue(ShellRecordRules.hasWalletData(tree))
        val buf = CharJson.CharBuf(); CharJson.write(ShellRecordRules.filterToWhitelist(tree)!!, buf)
        val s = String(buf.toArrayAndWipe())
        assertEquals("""{"profiles":[{"keyID":"k","tokens":{"a":1},"chatManager":{"router":{},"pgpKey":{"publicKey":"Q","keyID":"K"}}}]}""", s)
    }

    // ----------: encrypted native copy, W class approved ----------

    @Test
    fun encryptedStoreRoundTripAndTamperFails() {
        val f = File(tmp.newFolder(), "r/page-record.bsr")
        val cipher = RecordCipher.Software()
        val store = ShellRecordStore(f, cipher)
        val rec = CharJson.parse("""{"rev":0,"schemaVersion":1,"profiles":[{"privateKeyArmor":"0xEOA-SECRET-TEST","emailAddr":"e"}],"mnemonic":"alpha beta"}""".toCharArray()) as CharJson.J.Obj
        assertTrue(store.write(rec, 1))
        val raw = f.readBytes()
        assertTrue(raw.copyOfRange(0, 4).contentEquals(RecordCipher.MAGIC))
        val text = String(raw, Charsets.ISO_8859_1)
        assertFalse(text.contains("EOA-SECRET-TEST") || text.contains("alpha beta") || text.contains("emailAddr"))
        assertEquals(1, store.read()!!.rev)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 1).toByte(); f.writeBytes(raw)
        try { store.read(); org.junit.Assert.fail("tampered file must not open") } catch (e: java.io.IOException) { assertEquals("record_unreadable", e.message) }
        // another key cannot open it either
        assertTrue(store.write(CharJson.parse("""{"rev":0}""".toCharArray()) as CharJson.J.Obj, 1))
        try { ShellRecordStore(f, RecordCipher.Software()).read(); org.junit.Assert.fail() } catch (e: java.io.IOException) { }
    }

    @Test
    fun approvedWalletClassIsAcceptedButPgpStaysRefused() {
        val store = ShellRecordStore(File(tmp.newFolder(), "r/x.bsr"), RecordCipher.Software())
        val state = ShellRecordState().apply { walletCopyApproved = true }
        val b = ShellRecordBridge(store, state)
        fun w(rec: String) = JSONObject(b.handle(true, """{"type":"shellRecordWrite","reqId":"w","record":$rec}""", rec.length + 60))
        assertEquals("ok", w("""{"rev":0,"schemaVersion":1,"mnemonic":"m","profiles":[{"privateKeyArmor":"e","keyID":"k"}]}""").getString("code"))
        assertEquals("pgp_private_in_payload", w("""{"rev":1,"profiles":[{"chatManager":{"pgpKey":{"privateKey":"p"}}}]}""").getString("code"))
        assertEquals("bad_request", w("""{"rev":1,"profiles":[{"zzz":1}]}""").getString("code"))
        val read = JSONObject(b.handle(true, """{"type":"shellRecordRead","reqId":"r"}""", 40))
        assertEquals("ok", read.getString("code")); assertEquals(1, read.getJSONObject("record").getInt("rev"))
    }

    @Test
    fun startupWithRealPAndApprovalBuildsAnEncryptedPageRecordWithoutPgp() {
        val p = idbDirFromFixture()
        org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val idb = tmp.newFolder("idb3"); val dst = File(idb, p!!.name); p.copyRecursively(dst)
        val state = ShellRecordState().apply { walletCopyApproved = true }
        val f = File(tmp.newFolder(), "r/page.bsr")
        val store = ShellRecordStore(f, RecordCipher.Software())
        val runner = Recorder()
        val init = ShellRecordInit(dst, File(tmp.root, "copy3"), store, state, runner)
        init.prepare(); init.run()
        assertNull(state.initBlocked)
        assertEquals(1, runner.calls.size) // PGP from P to the migration entry
        val raw = String(f.readBytes(), Charsets.ISO_8859_1)
        assertFalse(raw.contains("PGP") || raw.contains("profiles"))
        val out = JSONObject(ShellRecordBridge(store, state).handle(true, """{"type":"shellRecordRead","reqId":"r"}""", 40))
        assertEquals("ok", out.getString("code"))
        val text = out.toString()
        assertFalse(text.contains("PGP PRIVATE KEY"))
        assertTrue(text.contains("PGP PUBLIC KEY"))
        assertEquals(1, out.getJSONObject("record").getInt("rev"))
        assertTrue(out.getJSONObject("record").getJSONArray("profiles").getJSONObject(0).has("privateKeyArmor")) // W class kept (/)
    }

    /**: the SDK owns the page record; the shell only reads P and hands the PGP to run(source). */
    @Test
    fun startupWithoutShellStoreOnlyHandsPgpToTheSdk() {
        val p = idbDirFromFixture()
        org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val idb = tmp.newFolder("idb4"); val dst = File(idb, p!!.name); p.copyRecursively(dst)
        val state = ShellRecordState()
        val runner = Recorder()
        val temp = File(tmp.root, "copy4")
        val init = ShellRecordInit(dst, temp, null, state, runner)
        init.prepare(); assertTrue(temp.exists()); init.run()
        assertEquals(1, runner.calls.size)
        assertEquals("0xb896bbb75a1ae81264a6d291250db6c6cd97ef5d", runner.calls[0].first)
        assertTrue(runner.heldPriv!!.all { it == 0.toByte() })
        assertNull(state.initBlocked)
        assertFalse(state.migrating)
        assertFalse(temp.exists())
    }

    // ----------: first page write to the SDK from P ----------

    private class FakeImporter(var has: Boolean? = false, var answer: (String) -> PageRecordImporter.Result = { e -> PageRecordImporter.Result("ok", e) }) : PageRecordImporter {
        val payloads = ArrayList<String>(); val eoas = ArrayList<String>(); val unreadable = ArrayList<String>()
        var lastBytes: ByteArray? = null
        override fun hasRecord() = has
        override fun importInitial(recordUtf8: ByteArray, expectedEoa: String): PageRecordImporter.Result {
            payloads += String(recordUtf8, Charsets.UTF_8); eoas += expectedEoa; lastBytes = recordUtf8
            return answer(expectedEoa)
        }
        override fun markLegacyUnreadable(code: String) { unreadable += code }
    }

    private fun fixtureCopy(name: String): File? {
        val p = idbDirFromFixture() ?: return null
        val dst = File(tmp.newFolder(name), p.name); p.copyRecursively(dst); return dst
    }

    private fun runInit(p: File, imp: FakeImporter, runner: Recorder = Recorder()): ShellRecordInit {
        val init = ShellRecordInit(p, File(tmp.root, "c-" + System.nanoTime()), null, ShellRecordState(), runner, importer = imp)
        init.prepare(); init.run(); return init
    }

    @Test
    fun firstWriteCarriesTheOldRecordWithoutPgpAndChecksTheAddress() {
        val p = fixtureCopy("fw1"); org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val imp = FakeImporter()
        val runner = Recorder()
        val init = runInit(p!!, imp, runner)
        assertEquals("ok", init.lastImportCode)
        assertEquals(listOf("0xb896bbb75a1ae81264a6d291250db6c6cd97ef5d"), imp.eoas)
        val body = imp.payloads.single()
        assertFalse(body.contains("PGP PRIVATE KEY"))
        // r3br: residual PGP public fields stripped from the first import (chatManager keeps only router)
        assertFalse(body.contains("\"pgpKey\"") || body.contains("pgpPublicKeyArmor") || body.contains("pgpPublicKeyID"))
        assertTrue(body.contains("\"privateKeyArmor\"") && body.contains("\"mnemonicPhrase\"")) // W class goes to the SDK copy
        assertTrue(imp.lastBytes!!.all { it == 0.toByte() })
        assertEquals(1, runner.calls.size) // PGP migration still runs from P
    }

    @Test
    fun aDifferentAddressFromTheSdkIsAMismatch() {
        val p = fixtureCopy("fw2"); org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val init = runInit(p!!, FakeImporter(answer = { PageRecordImporter.Result("ok", "0x" + "11".repeat(20)) }))
        assertEquals("address_mismatch", init.lastImportCode)
    }

    @Test
    fun failedImportKeepsOldDataAndRetriesNextLaunch() {
        val p = fixtureCopy("fw3"); org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val before = p!!.walkTopDown().filter { it.isFile }.associate { it.name to it.readBytes().contentHashCode() }
        val imp = FakeImporter(answer = { PageRecordImporter.Result("write_failed", null) })
        assertEquals("write_failed", runInit(p, imp).lastImportCode)
        assertEquals(before, p.walkTopDown().filter { it.isFile }.associate { it.name to it.readBytes().contentHashCode() }) // P untouched
        imp.answer = { e -> PageRecordImporter.Result("ok", e) }
        assertEquals("ok", runInit(p, imp).lastImportCode) // next launch: no SDK record yet → P read again
        assertEquals(2, imp.payloads.size)
    }

    @Test
    fun unreadableOldStoreIsReportedNotTreatedAsEmpty() {
        val p = tmp.newFolder("bad-idb"); File(p, "CURRENT").writeText("MANIFEST-000009\n") // manifest missing → unreadable
        val imp = FakeImporter()
        val runner = Recorder()
        val init = runInit(p, imp, runner)
        assertEquals("legacy_unreadable", init.lastImportCode)
        assertEquals(listOf("leveldb_corrupt"), imp.unreadable)
        assertTrue(imp.payloads.isEmpty())
        assertTrue(runner.calls.isEmpty())
        assertTrue(File(p, "CURRENT").isFile) // old data kept
    }

    @Test
    fun oldStoreIsNotReadOnceTheSdkHasARecord() {
        val p = fixtureCopy("fw5"); org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val imp = FakeImporter(has = true)
        val init = runInit(p!!, imp)
        assertNull(init.lastImportCode)
        assertTrue(imp.payloads.isEmpty())
    }

    // ---------- SDK 0.2.16 first-run path ----------

    private class FakeFirstRun(var code: String = "import_ok") : FirstRunImporter {
        val calls = ArrayList<Pair<String, String?>>(); val pending = ArrayList<Boolean>()
        override fun setMigrationPending(pending: Boolean) { this.pending += pending }
        override fun importFirstRun(eoa: String, record: ByteArray?, unreadableReason: String?, pgp: PgpMigrationRunner.Source?): String {
            calls += eoa to pgp?.let { String(it.privateArmor).take(36) }
            record?.fill(0); pgp?.privateArmor?.fill(0); pgp?.publicArmor?.fill(0)
            return code
        }
    }

    @Test
    fun sdkFirstRunIsCalledOnceThenPIsNeverReadAgain() {
        val p = fixtureCopy("sdk1"); org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val done = File(tmp.root, "nb/plan-n/first-run-done")
        val sdk = FakeFirstRun()
        fun launch(): ShellRecordInit {
            val temp = File(tmp.root, "t-" + System.nanoTime())
            val init = ShellRecordInit(p!!, temp, null, ShellRecordState(), Recorder(), firstRun = sdk, firstRunDone = done)
            init.prepare(); init.run(); assertFalse(temp.exists()); return init
        }
        assertEquals("import_ok", launch().lastImportCode)
        assertEquals(1, sdk.calls.size)
        assertEquals("0xb896bbb75a1ae81264a6d291250db6c6cd97ef5d", sdk.calls[0].first)
        assertTrue(sdk.calls[0].second!!.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK"))
        assertTrue(done.isFile)
        assertEquals(listOf(true, false), sdk.pending)
        assertEquals("0xb896bbb75a1ae81264a6d291250db6c6cd97ef5d", done.readText().trim()) // marker holds the public address only
        sdk.code = "exists"
        assertEquals("exists", launch().lastImportCode) // second launch: P not copied; one rebind call with the address, no record
        assertEquals(2, sdk.calls.size)
        assertEquals("0xb896bbb75a1ae81264a6d291250db6c6cd97ef5d", sdk.calls[1].first)
        assertNull(sdk.calls[1].second) // no PGP source on the rebind
    }

    @Test
    fun sdkFailureLeavesNoMarkerSoTheNextLaunchRetries() {
        val p = fixtureCopy("sdk2"); org.junit.Assume.assumeTrue("fixture not provided", p != null)
        val done = File(tmp.root, "nb2/first-run-done")
        val sdk = FakeFirstRun("import_failed")
        val i1 = ShellRecordInit(p!!, File(tmp.root, "t1"), null, ShellRecordState(), Recorder(), firstRun = sdk, firstRunDone = done)
        i1.prepare(); i1.run()
        assertEquals("import_failed", i1.lastImportCode); assertFalse(done.exists())
        sdk.code = "import_ok"
        val i2 = ShellRecordInit(p, File(tmp.root, "t2"), null, ShellRecordState(), Recorder(), firstRun = sdk, firstRunDone = done)
        i2.prepare(); i2.run()
        assertEquals("import_ok", i2.lastImportCode); assertEquals(2, sdk.calls.size)
    }

    @Test
    fun sdkPathConfirmsAbsenceAndReportsUnreadableWithThePlaceholder() {
        val sdk = FakeFirstRun("absent")
        val i1 = ShellRecordInit(File(tmp.root, "no-idb-x"), File(tmp.root, "ta"), null, ShellRecordState(), Recorder(), firstRun = sdk, firstRunDone = File(tmp.root, "m1"))
        i1.prepare(); i1.run()
        assertEquals("absent", i1.lastImportCode)
        assertEquals(ShellRecordInit.PLACEHOLDER_EOA, sdk.calls.single().first)
        assertNull(sdk.calls.single().second)

        val bad = tmp.newFolder("bad2"); File(bad, "CURRENT").writeText("MANIFEST-000009\n")
        val sdk2 = FakeFirstRun("legacy_unreadable")
        val i2 = ShellRecordInit(bad, File(tmp.root, "tb"), null, ShellRecordState(), Recorder(), firstRun = sdk2, firstRunDone = File(tmp.root, "m2"))
        i2.prepare(); i2.run()
        assertEquals("legacy_unreadable", i2.lastImportCode)
        assertTrue(File(bad, "CURRENT").isFile)
        assertFalse(File(tmp.root, "m2").exists()) // no marker: next launch retries
    }
}
