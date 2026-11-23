package com.beamio.app.credential

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Index x §25.2: inbound receive only; trusted source only; closed payload; lock-stop flag off. */
class PasscodeStateInboundTest {
    private fun state(set: Boolean = true, locked: Boolean = true): JSONObject =
        JSONObject().put("type", "passcodeState").put("set", set).put("locked", locked)

    private fun wrapped(inner: JSONObject): JSONObject =
        JSONObject().put("action", "chatModuleEvent").put("event", inner)

    @Test fun acceptsWrappedSdkEvent() {
        val (outcome, s) = PasscodeStateInbound.observe(wrapped(state()), PasscodeStateInbound.Source.SDK_NATIVE)
        assertEquals(PasscodeStateInbound.Outcome.ACCEPTED, outcome)
        assertEquals(PasscodeStateInbound.State(set = true, locked = true), s)
    }

    @Test fun acceptsBareSdkEvent() {
        val (outcome, _) = PasscodeStateInbound.observe(state(set = false, locked = false), PasscodeStateInbound.Source.SDK_NATIVE)
        assertEquals(PasscodeStateInbound.Outcome.ACCEPTED, outcome)
    }

    @Test fun pageSourceIsNeverAccepted() {
        val (outcome, s) = PasscodeStateInbound.observe(wrapped(state()), PasscodeStateInbound.Source.PAGE)
        assertEquals(PasscodeStateInbound.Outcome.IGNORED_SOURCE, outcome)
        assertNull(s)
    }

    @Test fun credentialFieldInPayloadIsRejected() {
        for (name in listOf("passcode", "phrase", "oldPasscode", "newPasscode", "mnemonic", "eoa")) {
            val ev = state().put(name, "x")
            val (outcome, s) = PasscodeStateInbound.observe(wrapped(ev), PasscodeStateInbound.Source.SDK_NATIVE)
            assertEquals("field $name", PasscodeStateInbound.Outcome.REJECTED_SHAPE, outcome)
            assertNull(s)
        }
    }

    @Test fun nonBooleanValueIsRejected() {
        val ev = JSONObject().put("type", "passcodeState").put("set", "yes").put("locked", true)
        assertEquals(PasscodeStateInbound.Outcome.REJECTED_SHAPE, PasscodeStateInbound.observe(wrapped(ev), PasscodeStateInbound.Source.SDK_NATIVE).first)
    }

    @Test fun otherEventsAreIgnored() {
        val ev = JSONObject().put("type", "nativeRepairResult").put("ok", true)
        assertEquals(PasscodeStateInbound.Outcome.IGNORED_NOT_EVENT, PasscodeStateInbound.observe(wrapped(ev), PasscodeStateInbound.Source.SDK_NATIVE).first)
    }

    @Test fun lockDoesNotStopWhileFlagOff() {
        assertEquals(false, PasscodeStateInbound.STOP_ON_PASSCODE_LOCKED)
        assertFalse(PasscodeStateInbound.shouldStopOnLock(PasscodeStateInbound.State(set = true, locked = true)))
    }
}
