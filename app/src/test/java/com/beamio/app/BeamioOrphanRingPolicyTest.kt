package com.beamio.app

import com.beamio.app.BeamioOrphanRingPolicy.Row
import org.junit.Assert.assertEquals
import org.junit.Test

class BeamioOrphanRingPolicyTest {
    private fun incomingRinging(key: String, vararg ids: String) = Row(key, incoming = true, ringing = true, ids = ids.toSet() + key)

    @Test
    fun invisibleRingingIncomingIsAnOrphan() {
        val rows = listOf(incomingRinging("old-call", "old-session"))
        assertEquals(listOf("old-call"), BeamioOrphanRingPolicy.orphans(rows, keepKeys = setOf("new-call"), liveCallKeys = emptySet()))
    }

    @Test
    fun outgoingDialIsNeverCleared() {
        // Samsung 2026-11-03: replayed offer after a crash; the DIALING call 08adc6d2 was torn.
        val dialing = Row("08adc6d2", incoming = false, ringing = false, ids = setOf("08adc6d2"))
        assertEquals(emptyList<String>(), BeamioOrphanRingPolicy.orphans(listOf(dialing), setOf("replayed"), emptySet()))
        // Even with no native call or call page known for it.
        val dialingRingingFlag = Row("08adc6d2", incoming = false, ringing = true, ids = setOf("08adc6d2"))
        assertEquals(emptyList<String>(), BeamioOrphanRingPolicy.orphans(listOf(dialingRingingFlag), emptySet(), emptySet()))
    }

    @Test
    fun answeredOrHeldIncomingIsNotRinging() {
        val active = Row("a", incoming = true, ringing = false, ids = setOf("a"))
        assertEquals(emptyList<String>(), BeamioOrphanRingPolicy.orphans(listOf(active), emptySet(), emptySet()))
    }

    @Test
    fun offerBeingPresentedIsKept() {
        val rows = listOf(incomingRinging("tc-1", "call-x", "session-x"))
        assertEquals(emptyList<String>(), BeamioOrphanRingPolicy.orphans(rows, keepKeys = setOf("session-x"), liveCallKeys = emptySet()))
    }

    @Test
    fun callInProgressIsKeptByAnyId() {
        val rows = listOf(incomingRinging("tc-2", "call-y", "listen-y"))
        assertEquals(emptyList<String>(), BeamioOrphanRingPolicy.orphans(rows, emptySet(), liveCallKeys = setOf(" listen-y ")))
    }

    @Test
    fun blankKeysProtectNothing() {
        val rows = listOf(incomingRinging("tc-3", "call-z"))
        assertEquals(listOf("tc-3"), BeamioOrphanRingPolicy.orphans(rows, keepKeys = setOf("", " "), liveCallKeys = setOf("")))
    }

    @Test
    fun onlyTheOrphansOfAMixedSetAreCleared() {
        val rows = listOf(
            incomingRinging("orphan"),
            Row("dial", incoming = false, ringing = false, ids = setOf("dial")),
            incomingRinging("new", "new-session"),
        )
        assertEquals(listOf("orphan"), BeamioOrphanRingPolicy.orphans(rows, keepKeys = setOf("new-session"), liveCallKeys = setOf("dial")))
    }
}
