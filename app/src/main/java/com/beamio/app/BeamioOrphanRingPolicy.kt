package com.beamio.app

/**
 * Which Telecom connections a new incoming report may clear as "ringing with
 * no window" (BAL Abort leaves those behind and they busy-block later dials).
 *
 * Only an incoming call that is still RINGING can be such an orphan. Never:
 * - an outgoing call (Samsung, 2026-11-03: a cold start replayed an offer and
 *   this sweep removed the DIALING call, the dial page closed and the callee
 *   rang until timeout);
 * - a call the user is in or dialing ([liveCallKeys]: native call, call page);
 * - the offer being presented now ([keepKeys]).
 */
internal object BeamioOrphanRingPolicy {
    data class Row(
        val key: String,
        val incoming: Boolean,
        val ringing: Boolean,
        val ids: Set<String>,
    )

    fun orphans(
        rows: List<Row>,
        keepKeys: Set<String>,
        liveCallKeys: Set<String>,
    ): List<String> {
        val keep = keepKeys.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val live = liveCallKeys.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        return rows.filter { row ->
            if (!row.incoming || !row.ringing) return@filter false
            val ids = row.ids + row.key
            ids.none { keep.contains(it) } && ids.none { live.contains(it) }
        }.map { it.key }
    }
}
