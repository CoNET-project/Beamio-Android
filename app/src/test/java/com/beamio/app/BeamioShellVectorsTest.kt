package com.beamio.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * window.BeamioShell channel vectors (spec r3gi §25.52EI): protocol/beamioshell-channel-vectors.v1.json,
 * pinned sha256 below, BS-01 to BS-12 (queryIncomingCallOutcome). Each case goes through BeamioShellChannel.decide and
 * IncomingCallOutcome.respond; the ack and every event are compared key set for key set (§25.52EC.2: no extra or missing
 * keys), events in order.
 */
class BeamioShellVectorsTest {
    private val pinned = "5004af6d5f63ffaa03ab8bd88c8a3c858a253011dbe370531f70335bbfd3876d"
    private val trusted = "https://appassets.androidplatform.net"

    private fun load(): Pair<ByteArray, JSONObject> {
        val bytes = checkNotNull(javaClass.classLoader!!.getResourceAsStream("vectors/beamioshell-channel-vectors.v1.json")).readBytes()
        return bytes to JSONObject(String(bytes, Charsets.UTF_8))
    }

    /** Deep equality with exact key sets (numbers compared by value). */
    private fun same(path: String, want: Any?, got: Any?) {
        when (want) {
            is JSONObject -> {
                assertTrue("$path: object expected, got $got", got is JSONObject)
                val g = got as JSONObject
                assertEquals("$path keys", want.keys().asSequence().toSortedSet(), g.keys().asSequence().toSortedSet())
                for (k in want.keys()) same("$path.$k", want.get(k), g.get(k))
            }
            is JSONArray -> {
                assertTrue("$path: array expected", got is JSONArray)
                val g = got as JSONArray
                assertEquals("$path length", want.length(), g.length())
                for (i in 0 until want.length()) same("$path[$i]", want.get(i), g.get(i))
            }
            is Number -> assertEquals(path, want.toLong(), (got as Number).toLong())
            else -> assertEquals(path, want, got)
        }
    }

    @Test
    fun pinnedVectorFile() {
        val (bytes, d) = load()
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(pinned, sha)
        assertEquals(12, d.getJSONArray("cases").length())
        assertEquals(IncomingCallOutcome.RETENTION_MS, d.getJSONObject("fixture").getLong("retentionMs"))
        assertEquals(IncomingCallOutcome.MAX_BATCH, d.getJSONObject("fixture").getInt("maxBatch"))
    }

    @Test
    fun everyCase() {
        val cases = load().second.getJSONArray("cases")
        val ran = ArrayList<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val fx = c.getJSONObject("fixture")
            val records = fx.getJSONArray("ringRecords")
            // Records go through the same key function the shell's writer uses (IncomingCallOutcome.recordKeys).
            val store = HashSet<String>()
            for (k in 0 until records.length()) {
                val r = records.getJSONObject(k)
                store += IncomingCallOutcome.recordKeys(listOf(r.getString("callId"), r.getString("sessionId")), r.getString("callId"), r.getString("sessionId"))
            }
            val d = BeamioShellChannel.decide(c.getJSONObject("request").toString(), trusted, true)
            assertTrue("$id reaches the action", d is BeamioShellChannel.Decision.Call)
            val call = d as BeamioShellChannel.Decision.Call
            assertEquals(IncomingCallOutcome.ACTION, call.action)
            val (ack, events) = IncomingCallOutcome.respond(call.reqId, call.args, fx.getLong("nowMs")) { a, b -> IncomingCallOutcome.hasPair({ it in store }, a, b) }
            val expect = c.getJSONObject("expect")
            same("$id.ack", expect.getJSONObject("ack"), ack)
            val we = expect.getJSONArray("events")
            assertEquals("$id events", we.length(), events.size)
            for (k in 0 until we.length()) {
                assertEquals("$id.events[$k].channel", "cashtreesandroid", we.getJSONObject(k).getString("channel"))
                same("$id.events[$k]", we.getJSONObject(k).getJSONObject("payload"), events[k])
            }
            ran += id
        }
        println("EVIDENCE beamioshell-vectors sha=$pinned cases=${ran.joinToString(",")}")
        assertEquals((1..12).map { "BS-%02d".format(it) }, ran)
    }

    /** Writer and reader agree on the key (no trim), empty ids never stored or matched, per-id keys never match. */
    @Test
    fun recordAndQueryUseTheSameKey() {
        val store = HashSet<String>()
        store += IncomingCallOutcome.recordKeys(listOf(" c-1 ", "s-1", "native-9"), " c-1 ", "s-1")
        store += IncomingCallOutcome.recordKeys(listOf("", ""), "", "")
        store += IncomingCallOutcome.recordKeys(listOf("c-2", ""), "c-2", "")
        val has = { c: String, s: String -> IncomingCallOutcome.hasPair({ it in store }, c, s) }
        assertTrue(has(" c-1 ", "s-1"))
        assertTrue(!has("c-1", "s-1")) // exact: a trimmed query does not match an untrimmed record
        assertTrue(!has("", ""))
        assertTrue(!has("c-2", ""))
        assertTrue(!has("native-9", "s-1")) // per-id keys are not pairs
        assertTrue(store.none { it == IncomingCallOutcome.pairKey("", "") })
        // The service methods use exactly these helpers.
        val tel = java.io.File("src/main/java/com/beamio/app/BeamioTelecomService.kt").readText()
        assertTrue(tel.contains("val keys = IncomingCallOutcome.recordKeys(ids, callId, sessionId)"))
        assertTrue(tel.contains("return IncomingCallOutcome.hasPair({ prefs.contains(it) }, callId, sessionId)"))
    }

    /** The dispatcher sends the ack before the events and never drops rang (source check). */
    @Test
    fun wiring() {
        val src = java.io.File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(src.contains("IncomingCallOutcome.respond(c.reqId, c.args, System.currentTimeMillis())"))
        assertTrue(src.contains("if (events.isNotEmpty()) mainHandler.post { events.forEach { dispatchAndroidBridgeJsonToWeb(it) } }"))
        val tel = java.io.File("src/main/java/com/beamio/app/BeamioTelecomService.kt").readText()
        assertTrue(tel.contains("noteIncomingRang(context, listOf(callId, sessionId, nativeCallId), callId, sessionId)"))
    }
}
