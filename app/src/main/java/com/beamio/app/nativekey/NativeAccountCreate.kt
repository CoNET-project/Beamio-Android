package com.beamio.app.nativekey

import java.lang.ref.WeakReference

/**
 * Native account create (spec r3w 25.46, r3ap 25.50). QA shell side only.
 *
 * - The page sends `nativeAccountCreateOpen`; the SDK answers it and calls the launcher registered by the SDK binding,
 *   which opens [NativeAccountCreateActivity] through [NativeAccountCreateRoute].
 * - The page has one confirm button. On confirm the SDK generates, stores and reads back the key on a worker thread
 *   and sends `nativeAccountCreateResult` (code, plus `eoa` with `ok`) to the web page itself. No key, mnemonic or
 *   other secret passes through the shell or the web page.
 * - On close the shell calls the SDK's `pageClosed()`: with no result yet the SDK sends `cancelled`.
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

/** Connects the SDK's `NativeAccountCreateHost.launcher` to the activity on screen (MainActivity registers itself). */
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

    /** Called by the SDK launcher. `true` only when the page was (or is being) shown. */
    fun open(): Boolean {
        if (!NativeAccountCreateBackends.current.supported) return false
        val o = synchronized(this) { opener?.get() } ?: return false
        return o()
    }
}
