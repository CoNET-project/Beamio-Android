package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Admission rules on the PWA rev2 vector (signature step real; decrypt step not covered). */
class VoiceOfferAdmissionTest {
    private val signText = "CoNET voice_call_offer_v3\ncallId:vt-call-0001\nsessionId:vt-session-0001\nto:0x000000000000000000000000000000000000dead\ncreatedAt:1795217195851\nexpiresAt:1795218095851\ntimestamp:1795217195851\ncodec:audio/pcm;rate=16000\ncallerPgp:VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==\ncallerRoute:VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ"
    private val signature = "0xf814f04f44d3342c013041364877442c7f0de864e092ca16c72dd30a4531422328b05dc310274b8e05c23e247c3437d912db10eb2af05a11c1b2899375a51d8c1c"
    private val signer = "0x660fc041ffe39750ef53149debb5cf2df32c5b0f"
    private val from = "0x660fC041FFE39750eF53149debB5cF2dF32C5B0f"
    private val created = 1795217195851L
    private val validUntil = 1795218095851L

    private fun recovered(text: String = signText, sig: String = signature): String? =
        BeamioNativeEthSigner.recoverAddress(text, sig)

    @Test fun positiveRecoversSignerAndFromMatches() {
        assertEquals(signer, recovered()?.lowercase())
        assertNull(VoiceOfferAdmission.checkFrom(recovered(), from))
    }

    @Test fun oneByteChangedCallIdIsRejectedAtFromCheck() {
        val changed = signText.replace("callId:vt-call-0001", "callId:vt-call-0002")
        val r = recovered(changed)
        assertFalse(r?.lowercase() == signer)
        assertEquals(VoiceOfferAdmission.Reject.FROM_MISMATCH, VoiceOfferAdmission.checkFrom(r, from))
    }

    @Test fun fromNotSignerIsRejected() {
        val claimed = "0x1111111111111111111111111111111111111111"
        assertEquals(VoiceOfferAdmission.Reject.FROM_MISMATCH, VoiceOfferAdmission.checkFrom(recovered(), claimed))
    }

    @Test fun missingFromIsRejected() {
        assertEquals(VoiceOfferAdmission.Reject.FROM_MISSING, VoiceOfferAdmission.checkFrom(recovered(), null))
    }

    @Test fun expiredAndSkewRejected() {
        assertEquals(VoiceOfferAdmission.Reject.EXPIRED, VoiceOfferAdmission.checkWindow(validUntil + 1, created, validUntil))
        // Future issuedAt beyond 300 s is refused; a past issuedAt inside the window is accepted.
        assertEquals(VoiceOfferAdmission.Reject.SKEW, VoiceOfferAdmission.checkWindow(created - 300_001L, created, validUntil))
        assertNull(VoiceOfferAdmission.checkWindow(created - 300_000L, created, validUntil))
        assertNull(VoiceOfferAdmission.checkWindow(created + 600_000L, created, validUntil))
        assertNull(VoiceOfferAdmission.checkWindow(validUntil, created, validUntil))
    }

    @Test fun admitRecordsNothingOnRefusal() {
        var now = created
        val table = VoiceOfferAdmission.DedupeTable { now }
        val v = VoiceOfferAdmission.admit(table, now, recovered(), "0x1111111111111111111111111111111111111111",
            "vt-call-0001", "vt-session-0001", created, validUntil)
        assertTrue(v is VoiceOfferAdmission.Verdict.Refuse)
        assertEquals(0, table.size())
    }

    @Test fun dedupeKeyIsJsonArray() {
        assertEquals("[\"a\",\"b\"]", VoiceOfferAdmission.dedupeKey("a", "b"))
    }

    @Test fun perCallerQuotaRefusesOnlyThatCaller() {
        var now = 0L
        val table = VoiceOfferAdmission.DedupeTable { now }
        val r = "0x" + "a".repeat(40)
        repeat(VoiceOfferAdmission.PER_CALLER_CAP) { i -> table.record("k$i", r, validUntil) }
        assertEquals(VoiceOfferAdmission.Reject.PER_CALLER_FULL, table.admit("kx", r))
        assertNull(table.admit("ky", "0x" + "b".repeat(40)))
    }

    @Test fun globalFullWithUnexpiredRecordsRefuses() {
        var now = 0L
        val table = VoiceOfferAdmission.DedupeTable { now }
        repeat(VoiceOfferAdmission.GLOBAL_CAP) { i -> table.record("g$i", "0x" + (i % 40 + 10).toString(16).padStart(40, '0'), validUntil) }
        assertEquals(VoiceOfferAdmission.GLOBAL_CAP, table.size())
        assertEquals(VoiceOfferAdmission.Reject.GLOBAL_FULL, table.admit("new", "0x" + "c".repeat(40)))
        // Unexpired records are not evicted: still full after the attempt.
        assertEquals(VoiceOfferAdmission.GLOBAL_CAP, table.size())
    }

    @Test fun expiredRecordsAreEvictedWhenFull() {
        var now = 0L
        val table = VoiceOfferAdmission.DedupeTable { now }
        repeat(VoiceOfferAdmission.GLOBAL_CAP) { i -> table.record("g$i", "0x" + (i % 40 + 10).toString(16).padStart(40, '0'), validUntil) }
        now = VoiceOfferAdmission.RETENTION_MS + 1
        assertNull(table.admit("new", "0x" + "c".repeat(40)))
        assertEquals(0, table.size())
    }

    @Test fun recordedKeyIsSeenAsDuplicate() {
        var now = 0L
        val table = VoiceOfferAdmission.DedupeTable { now }
        val key = VoiceOfferAdmission.dedupeKey("vt-call-0001", "vt-session-0001")
        table.record(key, signer, validUntil)
        assertTrue(table.isRecorded(key))
    }
}
