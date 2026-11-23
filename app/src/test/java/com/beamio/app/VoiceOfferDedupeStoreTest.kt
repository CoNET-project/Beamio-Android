package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class VoiceOfferDedupeStoreTest {
    private fun tmpFile(): File {
        val dir = Files.createTempDirectory("dedupe-test").toFile()
        return File(dir, "dedupe.json")
    }

    @Test fun recordSurvivesRestart() {
        val f = tmpFile()
        var now = 1_000L
        val a = VoiceOfferDedupeStore(f) { now }
        val key = VoiceOfferAdmission.dedupeKey("c1", "s1")
        assertNull(a.admit(key, "0x" + "a".repeat(40)))
        assertTrue(a.record(key, "0x" + "a".repeat(40), 900_000L))
        val b = VoiceOfferDedupeStore(f) { now }
        assertTrue(b.isRecorded(key))
        assertEquals(1, b.size())
    }

    @Test fun expiredRecordIsDroppedOnLoad() {
        val f = tmpFile()
        var now = 0L
        val a = VoiceOfferDedupeStore(f) { now }
        val key = VoiceOfferAdmission.dedupeKey("c2", "s2")
        a.record(key, "0x" + "b".repeat(40), 900_000L)
        now = VoiceOfferAdmission.RETENTION_MS + 1
        val b = VoiceOfferDedupeStore(f) { now }
        assertFalse(b.isRecorded(key))
        assertEquals(0, b.size())
    }

    @Test fun perCallerQuotaSurvivesRestart() {
        val f = tmpFile()
        var now = 0L
        val r = "0x" + "c".repeat(40)
        val a = VoiceOfferDedupeStore(f) { now }
        repeat(VoiceOfferAdmission.PER_CALLER_CAP) { i -> a.record("k$i", r, 900_000L) }
        val b = VoiceOfferDedupeStore(f) { now }
        assertEquals(VoiceOfferAdmission.Reject.PER_CALLER_FULL, b.admit("kx", r))
        assertNull(b.admit("ky", "0x" + "d".repeat(40)))
    }

    @Test fun keyIsJsonArrayAcrossRestart() {
        val f = tmpFile()
        val a = VoiceOfferDedupeStore(f) { 0L }
        a.record("[\"x\",\"y\"]", "0x" + "e".repeat(40), 900_000L)
        assertTrue(VoiceOfferDedupeStore(f) { 0L }.isRecorded("[\"x\",\"y\"]"))
    }

    @Test fun corruptFileIsIgnored() {
        val f = tmpFile()
        f.writeText("not json")
        val b = VoiceOfferDedupeStore(f) { 0L }
        assertEquals(0, b.size())
    }

    @Test fun admitOfferRefusesDuplicateAfterRecord() {
        val f = tmpFile()
        val store = VoiceOfferDedupeStore(f) { 1_000L }
        val r = "0x" + "f".repeat(40)
        val first = store.admitOffer(r, r, "c9", "s9", 1_000L, 900_000L)
        assertTrue(first is VoiceOfferAdmission.Verdict.Admit)
        val again = store.admitOffer(r, r, "c9", "s9", 1_000L, 900_000L)
        assertEquals(VoiceOfferAdmission.Verdict.Refuse(VoiceOfferAdmission.Reject.DUPLICATE), again)
        // Survives restart: the duplicate is still refused.
        val after = VoiceOfferDedupeStore(f) { 1_000L }.admitOffer(r, r, "c9", "s9", 1_000L, 900_000L)
        assertEquals(VoiceOfferAdmission.Verdict.Refuse(VoiceOfferAdmission.Reject.DUPLICATE), after)
    }

    @Test fun admitOfferRefusesWhenFromNotSigner() {
        val f = tmpFile()
        val store = VoiceOfferDedupeStore(f) { 1_000L }
        val v = store.admitOffer("0x" + "a".repeat(40), "0x" + "b".repeat(40), "c8", "s8", 1_000L, 900_000L)
        assertEquals(VoiceOfferAdmission.Verdict.Refuse(VoiceOfferAdmission.Reject.FROM_MISMATCH), v)
        assertEquals(0, store.size())
    }
}
