package com.beamio.app.legacy

/**
 * Minimal JSON parser and writer over CharArray. String values stay in CharArrays (never java.lang.String), so a
 * record that holds secrets can be wiped after use. Object keys are names (not secret) and are ordinary Strings.
 */
internal object CharJson {
    class Bad(msg: String) : Exception(msg)

    sealed class J {
        class Obj(val m: LinkedHashMap<String, J>) : J()
        class Arr(val a: ArrayList<J>) : J()
        class Str(val c: CharArray) : J()
        class Num(val raw: String) : J()
        class Bool(val b: Boolean) : J()
        object Null : J()
    }

    fun parse(s: CharArray): J {
        val p = P(s)
        val v = p.value()
        p.ws()
        if (p.i != s.size) throw Bad("trailing data")
        return v
    }

    private class P(val s: CharArray) {
        var i = 0
        fun ws() { while (i < s.size && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++ }
        fun value(): J {
            ws()
            if (i >= s.size) throw Bad("eof")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> J.Str(str())
                't' -> lit("true", J.Bool(true))
                'f' -> lit("false", J.Bool(false))
                'n' -> lit("null", J.Null)
                else -> num()
            }
        }
        fun lit(w: String, v: J): J {
            if (i + w.length > s.size || String(s, i, w.length) != w) throw Bad("literal")
            i += w.length; return v
        }
        fun num(): J {
            val st = i
            while (i < s.size && (s[i].isDigit() || s[i] in "+-.eE")) i++
            if (st == i) throw Bad("value at $st")
            return J.Num(String(s, st, i - st))
        }
        fun obj(): J {
            i++; val m = LinkedHashMap<String, J>(); ws()
            if (i < s.size && s[i] == '}') { i++; return J.Obj(m) }
            while (true) {
                ws(); if (i >= s.size || s[i] != '"') throw Bad("key")
                val kc = str(); val k = String(kc); kc.fill('\u0000')
                ws(); if (i >= s.size || s[i] != ':') throw Bad(":"); i++
                m[k] = value(); ws()
                if (i >= s.size) throw Bad("eof in object")
                if (s[i] == ',') { i++; continue }
                if (s[i] == '}') { i++; return J.Obj(m) }
                throw Bad("object sep")
            }
        }
        fun arr(): J {
            i++; val a = ArrayList<J>(); ws()
            if (i < s.size && s[i] == ']') { i++; return J.Arr(a) }
            while (true) {
                a += value(); ws()
                if (i >= s.size) throw Bad("eof in array")
                if (s[i] == ',') { i++; continue }
                if (s[i] == ']') { i++; return J.Arr(a) }
                throw Bad("array sep")
            }
        }
        fun str(): CharArray {
            i++
            val out = CharBuf()
            while (true) {
                if (i >= s.size) { out.wipe(); throw Bad("eof in string") }
                val ch = s[i++]
                when {
                    ch == '"' -> return out.toArrayAndWipe()
                    ch == '\\' -> {
                        if (i >= s.size) { out.wipe(); throw Bad("escape") }
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> out.add(e)
                            'b' -> out.add('\b'); 'f' -> out.add('\u000c'); 'n' -> out.add('\n'); 'r' -> out.add('\r'); 't' -> out.add('\t')
                            'u' -> {
                                if (i + 4 > s.size) { out.wipe(); throw Bad("\\u") }
                                out.add(String(s, i, 4).toInt(16).toChar()); i += 4
                            }
                            else -> { out.wipe(); throw Bad("escape $e") }
                        }
                    }
                    else -> out.add(ch)
                }
            }
        }
    }

    /** Growable char buffer that wipes its old storage when it grows. */
    class CharBuf {
        private var a = CharArray(64)
        var n = 0; private set
        fun add(c: Char) {
            if (n == a.size) { val b = a.copyOf(a.size * 2); a.fill('\u0000'); a = b }
            a[n++] = c
        }
        fun add(s: String) { for (c in s) add(c) }
        fun add(c: CharArray) { for (x in c) add(x) }
        fun toArrayAndWipe(): CharArray = a.copyOf(n).also { wipe() }
        fun wipe() { a.fill('\u0000'); n = 0 }
    }

    /** Writes [v] as JSON, skipping object members for which [skip] (path, key) returns true. */
    fun write(v: J, out: CharBuf, path: List<String> = emptyList(), skip: (List<String>, String) -> Boolean = { _, _ -> false }) {
        when (v) {
            is J.Obj -> {
                out.add('{'); var first = true
                for ((k, x) in v.m) {
                    if (skip(path, k)) continue
                    if (!first) out.add(','); first = false
                    writeStr(k.toCharArray(), out); out.add(':'); write(x, out, path + k, skip)
                }
                out.add('}')
            }
            is J.Arr -> {
                out.add('['); v.a.forEachIndexed { idx, x -> if (idx > 0) out.add(','); write(x, out, path + "[]", skip) }; out.add(']')
            }
            is J.Str -> writeStr(v.c, out)
            is J.Num -> out.add(v.raw)
            is J.Bool -> out.add(if (v.b) "true" else "false")
            J.Null -> out.add("null")
        }
    }

    private fun writeStr(c: CharArray, out: CharBuf) {
        out.add('"')
        for (ch in c) when {
            ch == '"' -> out.add("\\\"")
            ch == '\\' -> out.add("\\\\")
            ch < ' ' -> out.add("\\u%04x".format(ch.code))
            else -> out.add(ch)
        }
        out.add('"')
    }

    fun wipe(v: J) {
        when (v) {
            is J.Obj -> v.m.values.forEach { wipe(it) }
            is J.Arr -> v.a.forEach { wipe(it) }
            is J.Str -> v.c.fill('\u0000')
            else -> Unit
        }
    }
}
