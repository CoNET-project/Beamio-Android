package com.beamio.app.legacy

import android.content.Context
import network.conet.chat.nativekey.BeamioShellRecordImport
import network.conet.chat.nativekey.ShellOrigin
import org.json.JSONObject

/**
 * Supplies the SDK page bridge that [ShellRecordChannel] needs (`BeamioShellRecordImport.handle`).
 * Before this, [PageBridgeHandlers.current] was never assigned, so the channel never attached and every
 * `shellRecordRead` / `window.BeamioShellRecord` request was unanswered (the page then saw not_supported).
 *
 * The shell supplies the verified origin: an embedded-page request is EMBEDDED_PAGE, anything else OTHER.
 * With no application context available the answer is the channel's own fallback (never an empty success).
 */
object ShellRecordBridgeAdapter : PageBridgeHandler {
    @Volatile private var contextProvider: () -> Context? = { null }

    /** Installs this handler. Called once at startup with a provider of the application context. */
    fun install(provider: () -> Context?) {
        contextProvider = provider
        PageBridgeHandlers.current = this
    }

    override fun handle(embeddedPage: Boolean, body: String, requestBytes: Int): String {
        val context = contextProvider() ?: return ShellRecordReplies.fallback(body)
        val origin = if (embeddedPage) ShellOrigin.EMBEDDED_PAGE else ShellOrigin.OTHER
        val json = JSONObject(body)
        return BeamioShellRecordImport.handle(context, origin, json, requestBytes).toString()
    }
}
