package com.beamio.app.chatapi

import org.json.JSONObject

/**
 * The Chat SDK (network.conet:chat 0.2.6) starts from its own default API base, `https://beamio.app/api`, when an init does not
 * carry one. beamio.app resolves to a third-party parking host, so the shell pins the base on every init it hands to the SDK
 * (PM 2026-11-17, same rule as iOS 105). The default constant stays in the SDK binary and is overridden here; it is never used
 * for a request on this path.
 */
object ChatApiBase {
    const val PINNED = "https://beamio.ca/api"

    /** Sets `apiBaseUrl` to [PINNED] on an init command, and on any command that already carries the field. Returns [body]. */
    fun pin(body: JSONObject): JSONObject {
        if (body.optString("type") == "init" || body.has("apiBaseUrl")) {
            body.put("apiBaseUrl", PINNED)
        }
        return body
    }
}
