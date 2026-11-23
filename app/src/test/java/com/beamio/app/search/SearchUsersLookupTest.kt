package com.beamio.app.search

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.SocketTimeoutException

/** 2026-11-17: search-users goes to beamio.ca only, one checked redirect, no foreign host. */
class SearchUsersLookupTest {
    private val address = "0x1234567890abcdef1234567890abcdef12345678"

    /** Scripted transport: answers in order, records every requested URL. */
    private class Scripted(private vararg val answers: Any) : SearchUsersLookup.Transport {
        val requested = mutableListOf<String>()
        val timeouts = mutableListOf<Pair<Int, Int>>()
        override fun get(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): SearchUsersLookup.Response {
            requested += url
            timeouts += connectTimeoutMs to readTimeoutMs
            val next = answers[requested.size - 1]
            if (next is Throwable) throw next
            return next as SearchUsersLookup.Response
        }
    }

    private fun ok(body: String) = SearchUsersLookup.Response(200, null, body)
    private fun redirect(to: String?) = SearchUsersLookup.Response(302, to, null)
    private fun status(code: Int) = SearchUsersLookup.Response(code, null, null)

    @Test
    fun normalAnswerIsReturnedWithOneRequestToBeamioCa() {
        val t = Scripted(ok("""{"results":[]}"""))
        assertEquals("""{"results":[]}""", SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(1, t.requested.size)
        assertEquals(true, t.requested[0].startsWith("https://beamio.ca/api/search-users?keyward="))
    }

    @Test
    fun foreignHostRedirectIsRefusedAfterExactlyOneRequest() {
        val t = Scripted(redirect("https://evil.example/api/search-users?keyward=x"), ok("should-not-be-read"))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(1, t.requested.size)
    }

    @Test
    fun lookalikeHostRedirectIsRefused() {
        val t = Scripted(redirect("https://beamio.ca.evil.example/x"), ok("no"))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(1, t.requested.size)
    }

    @Test
    fun httpRedirectToBeamioCaIsRefused() {
        val t = Scripted(redirect("http://beamio.ca/api/search-users?keyward=x"), ok("no"))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(1, t.requested.size)
    }

    @Test
    fun allowedHttpsRedirectOnBeamioCaIsFollowedOnce() {
        val t = Scripted(redirect("https://beamio.ca/api/search-users?keyward=y"), ok("""{"results":[]}"""))
        assertEquals("""{"results":[]}""", SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(2, t.requested.size)
    }

    @Test
    fun secondRedirectIsNotFollowed() {
        val t = Scripted(redirect("https://beamio.ca/a"), redirect("https://beamio.ca/b"), ok("no"))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(2, t.requested.size)
    }

    @Test
    fun missingLocationIsRefused() {
        val t = Scripted(redirect(null), ok("no"))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(1, t.requested.size)
    }

    @Test
    fun nonTwoHundredIsNullAndNeverThrows() {
        val t = Scripted(status(500))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
        assertEquals(1, t.requested.size)
    }

    @Test
    fun timeoutIsNullAndNeverThrows() {
        val t = Scripted(SocketTimeoutException("timeout"))
        assertNull(SearchUsersLookup.fetchBody(address, transport = t))
    }

    @Test
    fun emptyBodyIsReturnedAsIsForTheCallerToHandle() {
        val t = Scripted(ok(""))
        assertEquals("", SearchUsersLookup.fetchBody(address, transport = t))
    }

    @Test
    fun telecomPathKeepsFourSecondTimeoutsOnEveryHop() {
        val t = Scripted(redirect("https://beamio.ca/api/search-users?keyward=y"), ok("""{"results":[]}"""))
        SearchUsersLookup.fetchBody(address, connectTimeoutMs = 4000, readTimeoutMs = 4000, transport = t)
        assertEquals(listOf(4000 to 4000, 4000 to 4000), t.timeouts)
    }

    @Test
    fun defaultTimeoutsAreTheOriginalValuesForOtherCallers() {
        val t = Scripted(ok("""{"results":[]}"""))
        SearchUsersLookup.fetchBody(address, transport = t)
        assertEquals(listOf(10_000 to 12_000), t.timeouts)
    }

    @Test
    fun allowedRedirectTargetRules() {
        assertEquals("https://beamio.ca/x", SearchUsersLookup.allowedRedirectTarget("https://beamio.ca/x"))
        assertEquals("https://BEAMIO.CA/x", SearchUsersLookup.allowedRedirectTarget("https://BEAMIO.CA/x"))
        assertNull(SearchUsersLookup.allowedRedirectTarget("https://beamio.app/x"))
        assertNull(SearchUsersLookup.allowedRedirectTarget("http://beamio.ca/x"))
        assertNull(SearchUsersLookup.allowedRedirectTarget("/relative"))
        assertNull(SearchUsersLookup.allowedRedirectTarget("https://user@beamio.ca/x"))
        assertNull(SearchUsersLookup.allowedRedirectTarget("https://beamio.ca:8443/x"))
        assertNull(SearchUsersLookup.allowedRedirectTarget(null))
    }
}
