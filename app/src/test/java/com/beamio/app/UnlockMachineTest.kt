package com.beamio.app

import com.beamio.app.UnlockMachine.Kind
import com.beamio.app.IncomingUnlockTimer.Phase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnlockMachineTest {
    private val call = "call-0001-abcdef"
    private val other = "call-0002-abcdef"
    private val eoa = "0x1111111111111111111111111111111111111111"

    private class Clock(var t: Long = 0L)

    private fun machine(c: Clock) = UnlockMachine { c.t }

    @Test fun startEmitsRequestWithLoadPhase() {
        val c = Clock()
        val m = machine(c)
        val out = m.start(call, eoa)
        assertEquals(1, out.size)
        assertEquals(Kind.REQUEST, out[0].kind)
        assertEquals("load", out[0].payload!!.getString("phase"))
        assertEquals(IncomingUnlockTimer.T_LOAD_MS, out[0].payload!!.getLong("remainingMs"))
        assertEquals(Phase.LOAD, m.phaseOf(call))
    }

    @Test fun shownSwitchesToInputOnceAndIgnoresRepeatsAndOtherCalls() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        m.shown(other)
        assertEquals(Phase.LOAD, m.phaseOf(call))
        m.shown(call)
        assertEquals(Phase.INPUT, m.phaseOf(call))
        m.shown(call)
        assertEquals(Phase.INPUT, m.phaseOf(call))
    }

    @Test fun unlockOkAuthorizesExactlyOnce() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        val first = m.unlockOk(call, eoa)
        assertEquals(listOf(Kind.AUTHORIZE), first.map { it.kind })
        assertTrue(m.unlockOk(call, eoa).isEmpty())
        assertNull(m.activeCallId())
    }

    @Test fun unlockOkForAnotherCallOrAccountIsIgnored() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        assertTrue(m.unlockOk(other, eoa).isEmpty())
        assertTrue(m.unlockOk(call, "0x2222222222222222222222222222222222222222").isEmpty())
        assertEquals(call, m.activeCallId())
    }

    @Test fun loadBudgetExpiresToCancel() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        c.t = IncomingUnlockTimer.T_LOAD_MS - 1
        assertTrue(m.tick().isEmpty())
        c.t = IncomingUnlockTimer.T_LOAD_MS
        val out = m.tick()
        assertEquals(listOf(Kind.CANCEL), out.map { it.kind })
        assertNull(m.activeCallId())
    }

    @Test fun inputBudgetIsRestartedByShownAndCountsFromThere() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        c.t = 4_000L
        m.shown(call)
        c.t = 4_000L + IncomingUnlockTimer.T_IN_MS - 1
        assertTrue(m.tick().isEmpty())
        c.t = 4_000L + IncomingUnlockTimer.T_IN_MS
        assertEquals(listOf(Kind.CANCEL), m.tick().map { it.kind })
    }

    @Test fun cancelAfterAuthorizeEmitsNothing() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        m.unlockOk(call, eoa)
        assertTrue(m.cancel(call).isEmpty())
    }

    @Test fun cancelBeforeAuthorizeEmitsCancel() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        assertEquals(listOf(Kind.CANCEL), m.cancel(call).map { it.kind })
        assertTrue(m.unlockOk(call, eoa).isEmpty())
    }

    @Test fun startingAnotherCallCancelsThePreviousOne() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        val out = m.start(other, eoa)
        assertEquals(listOf(Kind.CANCEL, Kind.REQUEST), out.map { it.kind })
        assertEquals(call, out[0].callId)
        assertEquals(other, m.activeCallId())
    }

    @Test fun restartingTheSameCallDoesNotCancelIt() {
        val c = Clock()
        val m = machine(c)
        m.start(call, eoa)
        val out = m.start(call, eoa)
        assertEquals(listOf(Kind.REQUEST), out.map { it.kind })
    }

    @Test fun invalidInputRefusesWithoutRequest() {
        val c = Clock()
        val m = machine(c)
        val out = m.start("short", eoa)
        assertEquals(listOf(Kind.CANCEL), out.map { it.kind })
        assertNull(m.activeCallId())
    }

    @Test fun deadlineFollowsThePhase() {
        val c = Clock(100L)
        val m = machine(c)
        m.start(call, eoa)
        assertEquals(100L + IncomingUnlockTimer.T_LOAD_MS, m.deadlineAt())
        m.shown(call)
        assertEquals(100L + IncomingUnlockTimer.T_IN_MS, m.deadlineAt())
    }
}
