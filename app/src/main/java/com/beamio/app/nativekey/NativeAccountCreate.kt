package com.beamio.app.nativekey

import java.lang.ref.WeakReference

/**
 * Native account create (spec r3w 25.46, r3ap 25.50; since 193 spec r3si/r3sj item 63: no native page).
 *
 * - The page sends `nativeAccountCreateOpen(tag)`; the SDK answers it and calls the launcher registered by the SDK binding. The shell's
 *   opener is headless: it starts [NativeAccountCreateBackend.confirm] on a background thread and shows nothing.
 * - The SDK generates, stores and reads back the key and sends `nativeAccountCreateResult` (code, plus `eoa` with `ok`) to the web page
 *   itself. No key, mnemonic or other secret passes through the shell or the web page.
 * - Registration (`accountCreateRegister {tag, password}`) is a separate trusted shell action ([ShellAccountCreateAction]).
 */
enum class CreateCode(val wire: String) {
    OK("ok"),
    CANCELLED("cancelled"),
    ALREADY_EXISTS("already_exists"),
    WRITE_FAILED("write_failed"),
    READBACK_FAILED("readback_failed"),
    ;

    companion object {
        /** Unknown codes count as a failed write: the page stays open for a retry. */
        fun fromWire(w: String): CreateCode = values().firstOrNull { it.wire == w } ?: WRITE_FAILED
    }
}

/** The SDK create engine. Results go to the web page from the SDK; the shell only sees the code. */
interface NativeAccountCreateBackend {
    val supported: Boolean

    /** Starts one create. [done] runs once with the code (any thread). */
    fun confirm(done: (CreateCode) -> Unit)

    /** The page closed (SDK `pageClosed()`). */
    fun pageClosed() = Unit

    /** No SDK create engine in this build. */
    object Unavailable : NativeAccountCreateBackend {
        override val supported = false
        override fun confirm(done: (CreateCode) -> Unit) = done(CreateCode.WRITE_FAILED)
    }
}

object NativeAccountCreateBackends {
    @Volatile
    var current: NativeAccountCreateBackend = NativeAccountCreateBackend.Unavailable
}

/** Connects the SDK's `NativeAccountCreateHost.launcher` to the headless opener (MainActivity registers it). */
object NativeAccountCreateRoute {
    private var opener: WeakReference<() -> Boolean>? = null

    @Synchronized
    fun register(open: () -> Boolean) {
        opener = WeakReference(open)
    }

    @Synchronized
    fun unregister(open: () -> Boolean) {
        if (opener?.get() === open) opener = null
    }

    /** Called by the SDK launcher. `true` only when the headless create was started. */
    fun open(): Boolean {
        if (!NativeAccountCreateBackends.current.supported) return false
        val o = synchronized(this) { opener?.get() } ?: return false
        return o()
    }
}
