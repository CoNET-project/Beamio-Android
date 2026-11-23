package com.beamio.app.credential

import org.json.JSONObject

/**
 * Native-to-page event exit of the window channel (frozen passcode protocol v1 §一第 4 条).
 *
 * - The proxy (the channel's reply object) is stored only after a request has passed the trusted verdict ([onTrusted]).
 * - An untrusted request never calls [onTrusted], so it never changes the proxy.
 * - [reset] runs when the channel is rebuilt; the proxy is then empty.
 * - With no proxy, [deliver] drops the event and returns the local diagnostic code [NO_EVENT_TARGET]. That code is never sent to the page.
 *
 * Generic over the proxy type so the rules are testable on the JVM without a WebView.
 */
class TrustedEventExit<P : Any> {
    @Volatile private var proxy: P? = null

    /** Called after a request passed the trusted verdict. */
    fun onTrusted(p: P) {
        proxy = p
    }

    /** Called when the channel is rebuilt: the stored proxy is cleared. */
    fun reset() {
        proxy = null
    }

    /** A top-level navigation started. When the new page is not trusted, the proxy is cleared and events are dropped. */
    fun onMainFrameNavigation(trustedPage: Boolean) {
        if (!trustedPage) proxy = null
    }

    /** Whether a proxy is stored right now. */
    fun hasTarget(): Boolean = proxy != null

    /** Sends [event] through [post] when a proxy is stored; otherwise drops it and returns [NO_EVENT_TARGET]. */
    fun deliver(event: String, post: (P, String) -> Unit): String? {
        val p = proxy ?: return NO_EVENT_TARGET
        post(p, event)
        return null
    }

    companion object {
        /** Local diagnostic code (never sent to the page) for an event dropped with no trusted proxy. */
        const val NO_EVENT_TARGET = "no_event_target"
    }
}

/** The outer envelope of a native event to the page: `{action: "chatModuleEvent", event: {type, ...}}`. */
fun chatModuleEventEnvelope(event: JSONObject): JSONObject =
    JSONObject().put("action", "chatModuleEvent").put("event", event)
