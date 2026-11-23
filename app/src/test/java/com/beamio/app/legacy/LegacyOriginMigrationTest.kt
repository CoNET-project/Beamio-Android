package com.beamio.app.legacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * legacy-pwa-origin-migration.v1 (shell side, synthetic fixtures only): native never reads the CURRENT origin's IndexedDB;
 * P comes only from the OLD origin; a definitive result (absent or a read) writes the marker and P is not read again; an
 * unknown result writes no marker and is retried a bounded number of times.
 */
class LegacyOriginMigrationTest {

    /** Fake SDK first-run import: records what the shell passed; answers like the SDK's absent/unreadable/import paths. */
    private class FakeFirstRun : FirstRunImporter {
        val calls = mutableListOf<Pair<String, String?>>() // (reason, eoa)
        override fun setMigrationPending(pending: Boolean) = Unit
        override fun importFirstRun(eoa: String, record: ByteArray?, unreadableReason: String?, pgp: PgpMigrationRunner.Source?): String {
            calls += (unreadableReason ?: if (record == null) "absent" else "record") to eoa
            return when {
                unreadableReason != null -> "legacy_store_unreadable"
                record == null -> "absent"
                else -> "import_ok"
            }
        }
    }

    private fun newRoot(): File = kotlin.io.createTempDir(prefix = "lpo-")

    /** Builds an init the way ShellRecordChannel.start does, with the old origin as the only P source. */
    private fun init(dataDir: File, marker: File, fake: FakeFirstRun, log: (String) -> Unit = {}): ShellRecordInit {
        val tmp = File(dataDir, "tmp-copy")
        return ShellRecordInit(
            webviewIdbDir = ShellRecordChannel.legacyOriginIdbDir(dataDir), tempDir = tmp, store = null,
            state = ShellRecordState(), runner = PgpMigrationRunner.Unavailable, log = log,
            importer = null, firstRun = fake, firstRunDone = marker,
        )
    }

    private fun currentOriginDir(dataDir: File): File =
        File(dataDir, "app_webview/Default/IndexedDB/https_appassets.androidplatform.net_0.indexeddb.leveldb").also { d ->
            d.mkdirs()
            // Deliberately unreadable: if native ever read the current origin it would report unreadable, not absent.
            File(d, "CURRENT").writeText("garbage")
            File(d, "MANIFEST-000001").writeBytes(ByteArray(64) { 0x5a })
        }

    @Test fun sourceIsTheOldOriginOnlyNeverTheCurrentOrigin() {
        val dir = newRoot()
        val src = ShellRecordChannel.legacyOriginIdbDir(dir)
        assertTrue(src.path, src.path.endsWith("https_beamio.app_0.indexeddb.leveldb"))
        assertFalse(src.path, src.path.contains("appassets"))
    }

    @Test fun currentOriginDataIsNotReadWhenTheOldOriginIsAbsent() {
        val dir = newRoot()
        currentOriginDir(dir) // current origin holds (unreadable) PWA data
        val fake = FakeFirstRun()
        val marker = File(dir, "first-run-done")
        init(dir, marker, fake).also { it.prepare(); it.run() }
        // Old origin absent → definitive absent, never the unreadable result the current origin would have produced.
        assertEquals(listOf("absent" to "0x0000000000000000000000000000000000000000"), fake.calls)
    }

    @Test fun definitiveAbsentWritesMarkerAndIsNotReadAgain() {
        val dir = newRoot()
        val fake = FakeFirstRun()
        val marker = File(dir, "first-run-done")
        init(dir, marker, fake).also { it.prepare(); it.run() }
        assertTrue("marker written after absent", marker.isFile)
        val before = fake.calls.size
        init(dir, marker, fake).also { it.prepare(); it.run() }
        assertEquals("no second read or SDK call after a definitive result", before, fake.calls.size)
    }

    @Test fun unknownResultWritesNoMarkerAndRetriesAreBounded() {
        val dir = newRoot()
        val old = ShellRecordChannel.legacyOriginIdbDir(dir)
        old.mkdirs()
        File(old, "CURRENT").writeText("garbage")
        File(old, "MANIFEST-000001").writeBytes(ByteArray(64) { 0x5a })
        val fake = FakeFirstRun()
        val marker = File(dir, "first-run-done")
        repeat(ShellRecordInit.MAX_UNKNOWN_ATTEMPTS) {
            init(dir, marker, fake).also { it.prepare(); it.run() }
        }
        assertFalse("unknown never writes the marker", marker.isFile)
        val unreadableCalls = fake.calls.size
        assertEquals(ShellRecordInit.MAX_UNKNOWN_ATTEMPTS, unreadableCalls)
        // Past the bound: P is not read and the SDK is not called again.
        init(dir, marker, fake).also { it.prepare(); it.run() }
        assertEquals(unreadableCalls, fake.calls.size)
        assertFalse(marker.isFile)
    }
}
