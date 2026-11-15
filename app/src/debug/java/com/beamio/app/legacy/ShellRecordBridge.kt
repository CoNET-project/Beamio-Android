package com.beamio.app.legacy

/**
 * Plan N page bridge logic (spec r3ay §25.52D.5–7, §25.52E.2–5). Transport-independent: [ShellRecordChannel] passes
 * the origin check result, the raw message and its UTF-8 size; this returns the reply JSON.
 *
 * Page commands (fixed set, §25.52E.2): `shellRecordRead {type, reqId}` and `shellRecordWrite {type, reqId, record}`.
 * `shellRecordMigrationState` is not in the page set and is refused as `bad_request` here.
 * Every reply passes an exit assertion (no PGP private field or header) before it leaves; the log records only
 * pass/fail and field-name counts.
 */
class ShellRecordBridge(
    private val store: ShellRecordStore,
    private val state: ShellRecordState,
    private val log: (String) -> Unit = {},
) {
    fun handle(originAllowed: Boolean, message: String, sizeBytes: Int): String {
        if (!originAllowed) return reply(null, "origin_refused")
        val chars = message.toCharArray()
        val req = try { CharJson.parse(chars) as? CharJson.J.Obj } catch (e: CharJson.Bad) { null } finally { chars.fill('\u0000') }
            ?: return reply(null, "bad_request", names = listOf("message"))
        try {
            val reqId = req.m["reqId"]
            val reqIdOut = reqIdJson(reqId) ?: return reply(null, "bad_request", names = listOf("reqId"))
            if (sizeBytes > ShellRecordRules.MAX_BYTES) return reply(reqIdOut, "too_large")
            val type = (req.m["type"] as? CharJson.J.Str)?.let { String(it.c) }
            return when (type) {
                "shellRecordRead" -> {
                    extra(req, setOf("type", "reqId"))?.let { return reply(reqIdOut, "bad_request", names = it) }
                    read(reqIdOut)
                }
                "shellRecordWrite" -> {
                    extra(req, setOf("type", "reqId", "record"))?.let { return reply(reqIdOut, "bad_request", names = it) }
                    write(reqIdOut, req.m["record"])
                }
                else -> reply(reqIdOut, "bad_request", names = listOf("type"))
            }
        } finally {
            CharJson.wipe(req)
        }
    }

    private fun read(reqId: String): String {
        if (state.migrating) return reply(reqId, "migrating")
        state.initBlocked?.let { return reply(reqId, "error", sub = it) }
        val stored = try { store.read() } catch (e: java.io.IOException) { return reply(reqId, "error", sub = "record_unreadable") }
            ?: return reply(reqId, "absent")
        try {
            val hits = LegacyRecord.pgpPrivateHits(stored.json)
            if (hits != 0) {
                log("shellRecord exit assert FAIL read pgpPrivateHits=$hits")
                return reply(reqId, "error", sub = "record_unreadable")
            }
            val out = StringBuilder().append("{\"reqId\":").append(reqId).append(",\"code\":\"ok\",\"schemaVersion\":")
                .append(ShellRecordRules.SCHEMA_VERSION).append(",\"record\":").append(stored.json).append('}').toString()
            if (out.toByteArray(Charsets.UTF_8).size > ShellRecordRules.MAX_BYTES) return reply(reqId, "too_large")
            log("shellRecord exit assert pass read rev=${stored.rev} pgpPrivateHits=0")
            return out
        } finally {
            stored.json.fill('\u0000')
        }
    }

    private fun write(reqId: String, record: CharJson.J?): String {
        if (record == null) return reply(reqId, "bad_request", names = listOf("record"))
        when (val c = ShellRecordRules.checkRecord(record, state.walletCopyApproved)) {
            is ShellRecordRules.Check.Refuse -> {
                log("shellRecord write refused ${c.code} names=${c.names.size}")
                return reply(reqId, c.code, names = c.names)
            }
            ShellRecordRules.Check.Ok -> Unit
        }
        if (state.migrating) return reply(reqId, "migrating")
        val obj = record as CharJson.J.Obj
        val wantRev = (obj.m["rev"] as CharJson.J.Num).raw.toLong()
        val current = try { store.read() } catch (e: java.io.IOException) { return reply(reqId, "write_failed") }
        val currentRev = current?.rev ?: 0L
        current?.json?.fill('\u0000')
        if (wantRev != currentRev) return reply(reqId, "conflict", currentRev = currentRev)
        if (!store.write(obj, currentRev + 1)) return reply(reqId, "write_failed")
        log("shellRecord write ok rev=${currentRev + 1}")
        return reply(reqId, "ok", rev = currentRev + 1)
    }

    private fun extra(req: CharJson.J.Obj, allowed: Set<String>): List<String>? = req.m.keys.filter { it !in allowed }.takeIf { it.isNotEmpty() }

    /** §25.28.3: string of 1–64 printable ASCII, or integer 0..2^53−1. Returns its JSON form, or null if invalid. */
    private fun reqIdJson(v: CharJson.J?): String? = when (v) {
        is CharJson.J.Str -> if (v.c.size in 1..64 && v.c.all { it in ' '..'~' }) quote(String(v.c)) else null
        is CharJson.J.Num -> v.raw.toLongOrNull()?.takeIf { it in 0..9007199254740991L }?.toString()
        else -> null
    }

    private fun quote(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun reply(reqId: String?, code: String, sub: String? = null, names: List<String>? = null, rev: Long? = null, currentRev: Long? = null): String {
        val sb = StringBuilder().append("{\"reqId\":").append(reqId ?: "null").append(",\"code\":").append(quote(code))
        sub?.let { sb.append(",\"sub\":").append(quote(it)) }
        names?.let { n -> sb.append(",\"names\":[").append(n.joinToString(",") { quote(it) }).append(']') }
        rev?.let { sb.append(",\"rev\":").append(it) }
        currentRev?.let { sb.append(",\"currentRev\":").append(it) }
        return sb.append('}').toString()
    }
}
