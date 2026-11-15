package com.beamio.app.legacy

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * V8 serializer version 16 (WebView 157 on the S25, R607 diagnosis `unsupported_format:v8 version 16`). Synthetic vectors from the
 * Android SDK line (`plan-n/v8-v16-vectors.json`, no wallet data): v16 objects are read; B/V and unknown tags, v17 and v12 fail closed (7 cases since V16-07, a view tag V).
 * Every case also asserts that the input is unchanged: the row bytes passed in, and the vectors file itself (PM R619).
 */
class IdbFormatV16Test {
    private val vectorsUrl = javaClass.classLoader!!.getResource("plan-n/v8-v16-vectors.json")!!
    private val fileBefore: ByteArray = vectorsUrl.readBytes()
    private val vectors: JSONArray = JSONObject(String(fileBefore, Charsets.UTF_8)).getJSONArray("vectors")

    @Test
    fun syntheticVectors() {
        assertEquals(7, vectors.length())
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            val id = v.getString("id")
            val hex = v.getString("hex")
            // Object store rows start with a varint row version before the Blink envelope.
            val row = byteArrayOf(0) + ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
            val rowBefore = row.copyOf()
            val expect = v.getJSONObject("expect")
            val outcome = try {
                Result.success(IdbFormat.parseV8(IdbFormat.unwrapValue(row)))
            } catch (e: IdbFormat.Unsupported) {
                Result.failure(e)
            }
            assertArrayEquals("$id: input row changed", rowBefore, row)
            assertArrayEquals("$id: vectors file changed", fileBefore, vectorsUrl.readBytes())
            when (expect.getString("result")) {
                "ok" -> {
                    val value = outcome.getOrElse { fail("$id: expected ok, got ${it.message}"); return }
                    assertEquals(id, canon(expect.get("value")), canon(plain(value)))
                }
                "refused" -> {
                    val e = outcome.exceptionOrNull() ?: run { fail("$id: expected refusal"); return }
                    assertEquals(id, expect.getString("error"), e.message)
                }
                else -> fail("$id: unknown expectation")
            }
        }
    }

    private fun plain(v: IdbFormat.V8): Any? = when (v) {
        is IdbFormat.V8.Obj -> JSONObject().also { o -> v.props.forEach { (k, x) -> o.put(k, plain(x) ?: JSONObject.NULL) } }
        is IdbFormat.V8.Arr -> JSONArray().also { a -> v.items.forEach { a.put(plain(it) ?: JSONObject.NULL) } }
        is IdbFormat.V8.Str -> v.text()
        is IdbFormat.V8.Num -> v.d
        is IdbFormat.V8.Bool -> v.b
        IdbFormat.V8.Null -> null
    }

    private fun canon(v: Any?): String = when (v) {
        is JSONObject -> v.keys().asSequence().sorted().joinToString(",", "{", "}") { k -> "\"$k\":" + canon(v.get(k)) }
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canon(v.get(it)) }
        is Number -> v.toDouble().toString()
        null, JSONObject.NULL -> "null"
        else -> "\"$v\""
    }
}
