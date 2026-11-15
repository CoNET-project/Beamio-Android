package com.beamio.app

/**
 * NFC card links are deprecated in the consumer shell (owner, 2026-11-15, PM R1664; card binding removed in GAP-17).
 *
 * A Beamio SUN URL (the link written on NFC cards: a `/sun` or `/api/sun` path, or the uid+e+c+m query) must never
 * open a page, leave for the system browser, or be mapped into the app, on the old domain or the new one.
 *
 * This is a BLOCK list, deliberately wider than the exact-host allow list in [BeamioWebHosts] (PM R1678): any host
 * whose name CONTAINS "beamio.app" or "beamio.ca" is covered, lookalikes such as beamio.app.evil.com included, so a
 * SUN-shaped link never reaches the system browser. This wide match is used for blocking only; allowing, mapping and
 * the allow list use exact host names (BeamioWebHosts) and must never use this function.
 *
 * One exemption (PM R1675, R1681): cashtrees.beamio.app itself and hosts ending in ".cashtrees.beamio.app" are not
 * blocked, as before the domain move (its purpose is under investigation by Cursor, PM R1671). The exemption uses exact
 * host names, not a substring, so a lookalike such as cashtrees.beamio.app.evil.example is blocked.
 */
object BeamioNfcSunBlock {
    private val SUN_QUERY = setOf("uid", "e", "c", "m")

    fun isBeamioHostForBlock(host: String?): Boolean {
        val h = host?.lowercase()?.trimEnd('.') ?: return false
        if (h == "cashtrees.beamio.app" || h.endsWith(".cashtrees.beamio.app")) return false // PM R1675/R1681: exact
        return h.contains("beamio.app") || h.contains("beamio.ca")
    }

    /** SUN shape: path contains /sun (covers /api/sun) or the query has uid, e, c and m. */
    fun isSunShape(path: String?, queryNames: Set<String>): Boolean {
        val p = path?.lowercase().orEmpty()
        if (p.contains("/sun")) return true
        return queryNames.containsAll(SUN_QUERY)
    }

    fun isBlockedSunUrl(host: String?, path: String?, queryNames: Set<String>): Boolean =
        isBeamioHostForBlock(host) && isSunShape(path, queryNames)
}
