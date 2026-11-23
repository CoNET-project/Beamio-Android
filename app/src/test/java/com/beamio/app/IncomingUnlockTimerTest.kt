package com.beamio.app

import com.beamio.app.IncomingUnlockTimer.Phase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IncomingUnlockTimerTest {
    @Test fun provisionalValuesAndRingBudget() {
        assertEquals(10_000L, IncomingUnlockTimer.T_LOAD_MS)
        assertEquals(45_000L, IncomingUnlockTimer.T_IN_MS)
        assertTrue(IncomingUnlockTimer.T_LOAD_MS + IncomingUnlockTimer.T_IN_MS <= 60_000L)
    }

    @Test fun remainingCountsDownAndClampsAtZero() {
        assertEquals(10_000L, IncomingUnlockTimer.remainingMs(Phase.LOAD, 0L))
        assertEquals(4_000L, IncomingUnlockTimer.remainingMs(Phase.LOAD, 6_000L))
        assertEquals(0L, IncomingUnlockTimer.remainingMs(Phase.LOAD, 99_000L))
    }

    @Test fun expiryAtBudgetNotBefore() {
        assertFalse(IncomingUnlockTimer.expired(Phase.LOAD, 9_999L))
        assertTrue(IncomingUnlockTimer.expired(Phase.LOAD, 10_000L))
        assertTrue(IncomingUnlockTimer.expired(Phase.INPUT, 45_000L))
    }

    @Test fun shownMovesLoadToInputOnly() {
        assertEquals(Phase.INPUT, IncomingUnlockTimer.afterShown(Phase.LOAD))
        assertEquals(Phase.INPUT, IncomingUnlockTimer.afterShown(Phase.INPUT))
    }

    @Test fun payloadCarriesTheSharedFields() {
        val p = IncomingUnlockTimer.payload("call-0001-abcdef", "0x1111111111111111111111111111111111111111", Phase.LOAD, 7_500L)!!
        assertEquals("call-0001-abcdef", p.getString("callId"))
        assertEquals("0x1111111111111111111111111111111111111111", p.getString("eoa"))
        assertEquals(7_500L, p.getLong("remainingMs"))
        assertEquals("load", p.getString("phase"))
        assertEquals(setOf("callId", "eoa", "remainingMs", "phase"), p.keys().asSequence().toSet())
    }

    @Test fun nonPositiveOrBlankRefusesPayload() {
        assertNull(IncomingUnlockTimer.payload("call-0001-abcdef", "0x1111111111111111111111111111111111111111", Phase.INPUT, 0L))
        assertNull(IncomingUnlockTimer.payload("", "0x1111111111111111111111111111111111111111", Phase.LOAD, 1_000L))
        assertNull(IncomingUnlockTimer.payload("call-0001-abcdef", "", Phase.LOAD, 1_000L))
        assertNull(IncomingUnlockTimer.payload("short", "0x1111111111111111111111111111111111111111", Phase.LOAD, 1_000L))
        assertNull(IncomingUnlockTimer.payload("call with space", "0x1111111111111111111111111111111111111111", Phase.LOAD, 1_000L))
        assertNull(IncomingUnlockTimer.payload("call-0001-abcdef", "0x" + "A".repeat(40), Phase.LOAD, 1_000L))
    }
}
