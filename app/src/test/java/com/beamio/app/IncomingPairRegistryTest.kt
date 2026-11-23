package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IncomingPairRegistryTest {
    @Test fun exactPairMatches() {
        val r = IncomingPairRegistry()
        r.record("call-0001-aaaa", "sess-0001")
        assertTrue(r.matches("call-0001-aaaa", "sess-0001"))
    }

    @Test fun sameCallIdDifferentSessionIsNotMatched() {
        val r = IncomingPairRegistry()
        r.record("call-0001-aaaa", "sess-0001")
        assertFalse(r.matches("call-0001-aaaa", "sess-0002"))
    }

    @Test fun sessionAloneIsNotMatched() {
        val r = IncomingPairRegistry()
        r.record("call-0001-aaaa", "sess-0001")
        assertFalse(r.matches("call-other-bbbb", "sess-0001"))
    }

    @Test fun removedRegistrationNoLongerMatches() {
        val r = IncomingPairRegistry()
        r.record("call-0001-aaaa", "sess-0001")
        r.remove("call-0001-aaaa")
        assertFalse(r.matches("call-0001-aaaa", "sess-0001"))
    }

    @Test fun blankIdsNeverMatch() {
        val r = IncomingPairRegistry()
        r.record("", "sess")
        assertFalse(r.matches("", "sess"))
    }
}
