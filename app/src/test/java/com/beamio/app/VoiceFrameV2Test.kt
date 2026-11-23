package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VoiceFrameV2Test {
    private val key = "0x" + "55".repeat(32) // throwaway synthetic key for this test only
    private val from = BeamioNativeEthSigner.address(key)!!.lowercase()
    private val now = 1_795_217_195_851L
    private val window = 60_000L

    private fun signed(type: String = "voice_end_v1", seq: Long = 1L, at: Long = now, signer: String = key, fromField: String = from): VoiceFrameV2.Frame {
        val text = VoiceFrameV2.canonicalText(type, "call-offer-0002", "sess-0002", fromField, at, seq)
        val sig = BeamioNativeEthSigner.signEip191(signer, text)!!
        return VoiceFrameV2.Frame(type, "call-offer-0002", "sess-0002", fromField, at, seq, sig)
    }

    @Test fun canonicalTextIsExactV2Layout() {
        val t = VoiceFrameV2.canonicalText("voice_end_v1", "c", "s", "0xABC", 5L, 7L)
        assertEquals("CoNET voice_frame_v2\ntype:voice_end_v1\ncallId:c\nsessionId:s\nfrom:0xabc\nat:5\nseq:7", t)
    }

    @Test fun validFrameIsAccepted() {
        assertNull(VoiceFrameV2.check(signed(), 0L, now, window))
    }

    @Test fun wrongSignerIsRejected() {
        val other = "0x" + "66".repeat(32)
        assertEquals(VoiceFrameV2.Reject.BAD_SIG, VoiceFrameV2.check(signed(signer = other), 0L, now, window))
    }

    @Test fun tamperedSeqIsRejectedBySignature() {
        val f = signed(seq = 1L).copy(seq = 2L)
        assertEquals(VoiceFrameV2.Reject.BAD_SIG, VoiceFrameV2.check(f, 0L, now, window))
    }

    @Test fun replayOrRegressionIsRejected() {
        val receiver = VoiceFrameV2.Receiver(window) { now }
        assertNull(receiver.accept(signed(seq = 1L)))
        assertEquals(VoiceFrameV2.Reject.SEQ_NOT_ADVANCING, receiver.accept(signed(seq = 1L)))
        assertNull(receiver.accept(signed(seq = 2L)))
        assertEquals(VoiceFrameV2.Reject.SEQ_NOT_ADVANCING, receiver.accept(signed(seq = 1L)))
    }

    @Test fun atOutsideWindowIsRejected() {
        assertEquals(VoiceFrameV2.Reject.AT_OUT_OF_WINDOW, VoiceFrameV2.check(signed(at = now - window - 1), 0L, now, window))
        assertNull(VoiceFrameV2.check(signed(at = now - window), 0L, now, window))
    }

    @Test fun newChannelStartsFromSeqZero() {
        val first = VoiceFrameV2.Receiver(window) { now }
        assertNull(first.accept(signed(seq = 3L)))
        val second = VoiceFrameV2.Receiver(window) { now }
        assertNull(second.accept(signed(seq = 1L)))
    }

    @Test fun notAllowedTypeIsRejected() {
        assertEquals(VoiceFrameV2.Reject.NOT_ALLOWED_TYPE, VoiceFrameV2.check(signed(type = "voice_media_v1"), 0L, now, window))
    }
}
