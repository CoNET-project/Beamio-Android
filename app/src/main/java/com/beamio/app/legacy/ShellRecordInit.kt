package com.beamio.app.legacy

import java.io.File

/** Source selection for the PGP migration, shell part (spec §25.52B.2, vectors SR-04 to SR-07). */
object LegacySourceSelect {
    sealed class Pick {
        /** Use P: the measured layout, on the profile whose keyID is the account. */
        class UseP(val pgp: LegacyPgp, val eoa: String) : Pick()
        /** P present but not usable: the SDK is not called with P; [code] is the result code. */
        class Refuse(val code: String) : Pick()
        /** No P: the SDK reads L (source = null). */
        object NoP : Pick()
    }

    private val EOA = Regex("^0x[0-9a-f]{40}$")

    fun select(record: LegacyRecord?, eoa: String?): Pick {
        if (record == null) return Pick.NoP
        val keys = record.pgpKeys()
        val measured = keys.filter { it.layout == "chatManager.pgpKey" }
        if (measured.isEmpty()) return if (keys.isEmpty()) Pick.NoP else Pick.Refuse("legacy_unreadable") // SR-05
        val account = (eoa ?: record.profileKeyId(measured.first().profileIndex))?.lowercase()?.takeIf { EOA.matches(it) }
            ?: return Pick.Refuse("account_mismatch")
        val hit = measured.firstOrNull { record.profileKeyId(it.profileIndex)?.lowercase() == account } ?: return Pick.Refuse("account_mismatch") // SR-04
        return Pick.UseP(hit, account)
    }
}

/**
 * SDK page wallet copy (R399, r3bf): the first write of the page record comes from P, before the WebView starts.
 * The SDK owns the store; the shell only hands over the old record without PGP private fields.
 */
interface PageRecordImporter {
    class Result(val code: String, val eoa: String?)

    /** true when the SDK already holds a page record (P is then never read again); null when unknown. */
    fun hasRecord(): Boolean?

    /** First write. [recordUtf8] is JSON without PGP private fields; the importer zero-fills it. */
    fun importInitial(recordUtf8: ByteArray, expectedEoa: String): Result

    /** P exists but cannot be read now: the SDK must answer page reads with an error (never absent). */
    fun markLegacyUnreadable(code: String)

    /** The pinned SDK has no page-copy entry yet: nothing is written. */
    object Unavailable : PageRecordImporter {
        override fun hasRecord(): Boolean? = null
        override fun importInitial(recordUtf8: ByteArray, expectedEoa: String): Result { recordUtf8.fill(0); return Result("sdk_entry_missing", null) }
        override fun markLegacyUnreadable(code: String) = Unit
    }
}

/**
 * SDK first-run import (Android SDK 0.2.16 r3bh, `BeamioPgpMigrationImport.importFirstRun`): one call that writes the page
 * wallet copy from P and, only after `import_ok`, runs the PGP migration. Implemented by the SDK binding (nativekeySdk).
 */
interface FirstRunImporter {
    fun setMigrationPending(pending: Boolean)

    /** [record] = JSON without PGP private fields (zero-filled by the callee), or null with [unreadableReason]. Returns the wire code. */
    fun importFirstRun(eoa: String, record: ByteArray?, unreadableReason: String?, pgp: PgpMigrationRunner.Source?): String
}

object FirstRunImporters { @Volatile var current: FirstRunImporter? = null }

/** Plan N run state shared by the channel and the first-run step (release and debug). */
class ShellRecordState {
    @Volatile var migrating: Boolean = false
    /** Sub-code when page record initialisation is blocked (e.g. `wallet_copy_not_approved`, `record_unreadable`). */
    @Volatile var initBlocked: String? = null
    /** Owner approval for a native copy of W class data (§25.52D.10). Not approved in this build. */
    @Volatile var walletCopyApproved: Boolean = false
}

/**
 * A shell-side page record store. Only the debug reference code implements it (ShellRecordStore, src/debug); release
 * and store builds pass null because the SDK owns the page record (R389, PM R677).
 */
interface LegacyPageStore {
    /** True when the shell already has a page record (an unreadable one counts as present). */
    fun hasRecord(): Boolean
    /** Writes P's record as the first page record: null when written, else the blocked sub-code. */
    fun firstWrite(record: LegacyRecord, walletCopyApproved: Boolean): String?
}

/** SDK page bridge (`BeamioShellRecordImport.handle`); the shell supplies the verified origin. */
interface PageBridgeHandler {
    fun handle(embeddedPage: Boolean, body: String, requestBytes: Int): String
}

object PageBridgeHandlers { @Volatile var current: PageBridgeHandler? = null }

/** SDK entry `BeamioPgpMigrationImport.run(eoa, workspace, source)` (spec §25.52D.3), behind an interface. */
interface PgpMigrationRunner {
    /** [privateArmor] and [publicArmor] are UTF-8 bytes; the runner zero-fills them. Returns the result code. */
    class Source(val privateArmor: ByteArray, val publicArmor: ByteArray, val keyId: String)

    fun run(eoa: String, workspace: String, source: Source?): String

    /** The pinned SDK has no public import entry yet: nothing runs, nothing is written. */
    object Unavailable : PgpMigrationRunner {
        override fun run(eoa: String, workspace: String, source: Source?): String {
            source?.privateArmor?.fill(0); source?.publicArmor?.fill(0)
            return "sdk_entry_missing"
        }
    }
}

/**
 * Plan N startup (spec §25.52D.9). Called before the WebView is created:
 *  1. [prepare] copies P (the WebView IndexedDB directory) to a private temp directory while no WebView holds it.
 *  2. [run] (any thread): page record initialisation from P (only when no native page record exists; blocked while
 *     W class data is not approved), then the PGP migration with P's PGP fields (or null → L). While it runs, page
 *     reads answer `migrating`. The temp copy is always deleted. P itself is never written.
 */
class ShellRecordInit(
    private val webviewIdbDir: File,
    private val tempDir: File,
    /** Native page record store, or null when the SDK owns the page record (R389): step 1 is then skipped. */
    private val store: LegacyPageStore?,
    private val state: ShellRecordState,
    private val runner: PgpMigrationRunner,
    private val log: (String) -> Unit = {},
    /** R389/R399: when the SDK owns the page record, the first write goes through this (store is then null). */
    private val importer: PageRecordImporter? = null,
    /** SDK 0.2.16: combined first-run import. When set, it replaces [importer] and [runner] for the P path. */
    private val firstRun: FirstRunImporter? = null,
    /** SDK path: written after `import_ok` or `exists`; once present, P is never read again (§25.52D.9). */
    private val firstRunDone: File? = null,
) {
    /** Result of the last first-write attempt (public code only), for receipts and tests. */
    @Volatile var lastImportCode: String? = null
        private set

    private var copied: File? = null
    /** prepare() skipped P because the first run is already done (marker or store): the SDK is not called again. */
    private var skippedDone = false

    /** Step 0, on the caller's thread, before any WebView exists. Sets `migrating` until [run] finishes. */
    fun prepare() {
        state.migrating = true
        firstRun?.setMigrationPending(true)
        val hasRecord = if (store != null) store.hasRecord()
        else importer?.hasRecord() == true || firstRunDone?.isFile == true
        if (hasRecord) { skippedDone = true; return } // P is never read again after the page has its own record
        if (!webviewIdbDir.isDirectory) return
        tempDir.deleteRecursively()
        tempDir.mkdirs()
        val dst = File(tempDir, webviewIdbDir.name)
        webviewIdbDir.copyRecursively(dst, overwrite = true)
        copied = dst
    }

    fun run() {
        if (firstRun != null) { runSdk(firstRun); return }
        var record: LegacyRecord? = null
        try {
            val src = copied
            var pBlocked = false
            if (src != null) {
                when (val r = LegacyPwaStore.read(src)) {
                    is LegacyPwaStore.Result.Found -> record = r.record
                    LegacyPwaStore.Result.NotFound -> Unit
                    is LegacyPwaStore.Result.Failed -> {
                        // Old data stays as it is; the next launch retries. Never treated as "no wallet".
                        state.initBlocked = "record_unreadable"; pBlocked = true
                        importer?.markLegacyUnreadable(r.code)
                        lastImportCode = "legacy_unreadable"
                        log("shellRecord init: P unreadable (${r.code}); old data kept, retry next launch")
                    }
                }
            }
            // Step 1: page record initialisation (only if the shell has no page record yet).
            if (store == null && importer != null) record?.let { rec -> firstWriteToSdk(rec, importer) }
            if (store != null) record?.let { rec ->
                when (val blocked = store.firstWrite(rec, state.walletCopyApproved)) {
                    null -> log("shellRecord init: page record rev=1")
                    "wallet_copy_not_approved" -> { state.initBlocked = blocked; log("shellRecord init blocked: wallet_copy_not_approved") }
                    else -> { state.initBlocked = blocked; log("shellRecord init: write failed") }
                }
            }
            // Step 2: PGP migration (source P when usable, else L).
            if (!pBlocked) {
                val code = when (val pick = LegacySourceSelect.select(record, null)) {
                    is LegacySourceSelect.Pick.UseP -> {
                        val priv = utf8(pick.pgp.privateArmor)
                        val pub = pick.pgp.publicArmor?.let { utf8(it) } ?: ByteArray(0)
                        runner.run(pick.eoa, "default", PgpMigrationRunner.Source(priv, pub, "")).also { priv.fill(0); pub.fill(0) }
                    }
                    is LegacySourceSelect.Pick.Refuse -> pick.code
                    LegacySourceSelect.Pick.NoP -> "no_p"
                }
                log("pgp migration step: $code")
            }
        } finally {
            record?.wipe()
            copied?.let { wipeDir(it) }
            tempDir.deleteRecursively()
            copied = null
            state.migrating = false
        }
    }

    companion object {
        /**
         * SDK 0.2.16 (r3bp) validates the address before it looks at Absent/Unreadable, but with no legacy record the shell has no
         * address. This syntactically valid placeholder only passes that check; the SDK binds nothing to it for Absent/Unreadable.
         * Reported to the SDK: accept no address for these two cases.
         */
        const val PLACEHOLDER_EOA = "0x0000000000000000000000000000000000000000"
    }

    /** SDK 0.2.16 path: read P, then one `importFirstRun` call (page copy + PGP after import_ok). Old data is never written. */
    private fun runSdk(sdk: FirstRunImporter) {
        var record: LegacyRecord? = null
        try {
            if (skippedDone) {
                // SDK 0.2.16 r3bs keeps the bound account only in memory; after a restart with no native key (G0) the page read fails.
                // Interim: rebind from the account address kept in the marker (public). The SDK finds the existing copy and answers
                // `exists` without writing anything. P is not read.
                val eoa = firstRunDone?.takeIf { it.isFile }?.readText()?.trim()?.lowercase()?.takeIf { Regex("^0x[0-9a-f]{40}$").matches(it) }
                if (eoa != null) {
                    lastImportCode = sdk.importFirstRun(eoa, null, null, null)
                    log("first run: already done; P not read; rebind → $lastImportCode")
                } else { lastImportCode = null; log("first run: already done; P not read") }
                return
            }
            val src = copied
            if (src == null) {
                // No legacy store on this device: confirm the absence to the SDK (fresh install → page gets `absent`).
                lastImportCode = sdk.importFirstRun(PLACEHOLDER_EOA, null, null, null)
                log("first run: no P; confirmed absent → $lastImportCode")
                return
            }
            when (val r = LegacyPwaStore.read(src)) {
                LegacyPwaStore.Result.NotFound -> {
                    lastImportCode = sdk.importFirstRun(PLACEHOLDER_EOA, null, null, null)
                    log("first run: P has no wallet record; confirmed absent → $lastImportCode")
                }
                is LegacyPwaStore.Result.Failed -> {
                    // Old data stays as it is; the SDK records legacy_store_unreadable; the next launch retries.
                    state.initBlocked = "record_unreadable"
                    lastImportCode = sdk.importFirstRun(PLACEHOLDER_EOA, null, r.code, null)
                    log("first run: P unreadable (${r.code}) → $lastImportCode; old data kept, retry next launch")
                }
                is LegacyPwaStore.Result.Found -> {
                    record = r.record
                    val pick = LegacySourceSelect.select(r.record, null)
                    val eoa = (pick as? LegacySourceSelect.Pick.UseP)?.eoa
                        ?: r.record.profileKeyId(r.record.pgpKeys().firstOrNull()?.profileIndex ?: 0)?.lowercase()
                    if (eoa == null || !Regex("^0x[0-9a-f]{40}$").matches(eoa)) { lastImportCode = "account_mismatch"; log("first run: no account address"); return }
                    val bytes = r.record.pageCopyUtf8()
                    val hits = LegacyRecord.pgpPrivateHits(String(bytes, Charsets.UTF_8).toCharArray())
                    if (hits != 0) { bytes.fill(0); lastImportCode = "pgp_private_in_payload"; log("first run: exit assert FAIL pgpPrivateHits=$hits"); return }
                    val pgp = (pick as? LegacySourceSelect.Pick.UseP)?.let { u ->
                        PgpMigrationRunner.Source(utf8(u.pgp.privateArmor), u.pgp.publicArmor?.let { utf8(it) } ?: ByteArray(0), "")
                    }
                    lastImportCode = try { sdk.importFirstRun(eoa, bytes, null, pgp) } finally { bytes.fill(0); pgp?.privateArmor?.fill(0); pgp?.publicArmor?.fill(0) }
                    if (lastImportCode == "import_ok" || lastImportCode == "exists") {
                        firstRunDone?.let { m -> runCatching { m.parentFile?.mkdirs(); m.writeText(eoa + "\n") } } // public address only
                    }
                    log("first run: $lastImportCode (pgp source ${if (pgp != null) "P" else "L"})")
                }
            }
        } finally {
            record?.wipe()
            copied?.let { wipeDir(it) }
            tempDir.deleteRecursively()
            copied = null
            state.migrating = false
            sdk.setMigrationPending(false)
        }
    }

    /** R399: hand the old record (no PGP private fields) to the SDK as the first page write; check the address. */
    private fun firstWriteToSdk(rec: LegacyRecord, importer: PageRecordImporter) {
        val primary = rec.pgpKeys().firstOrNull()?.profileIndex ?: 0
        val expected = rec.profileKeyId(primary)?.lowercase()
        if (expected == null || !Regex("^0x[0-9a-f]{40}$").matches(expected)) {
            lastImportCode = "account_mismatch"; log("page copy: no account address in the old record; nothing written"); return
        }
        val bytes = rec.pageCopyUtf8()
        val hits = LegacyRecord.pgpPrivateHits(String(bytes, Charsets.UTF_8).toCharArray())
        if (hits != 0) { bytes.fill(0); lastImportCode = "pgp_private_in_payload"; log("page copy: exit assert FAIL pgpPrivateHits=$hits"); return }
        val r = try { importer.importInitial(bytes, expected) } finally { bytes.fill(0) }
        lastImportCode = when {
            r.code != "ok" -> r.code
            r.eoa?.lowercase() != expected -> "address_mismatch"
            else -> "ok"
        }
        log("page copy first write: $lastImportCode")
    }

    private fun utf8(c: CharArray): ByteArray {
        val bb = Charsets.UTF_8.encode(java.nio.CharBuffer.wrap(c))
        val out = ByteArray(bb.remaining()); bb.get(out)
        if (bb.hasArray()) bb.array().fill(0)
        return out
    }

    /** Overwrites the copied files with zeros before deleting them (best effort on flash storage). */
    private fun wipeDir(d: File) {
        d.walkBottomUp().forEach { f -> if (f.isFile) runCatching { f.writeBytes(ByteArray(f.length().toInt())) }; f.delete() }
    }
}
