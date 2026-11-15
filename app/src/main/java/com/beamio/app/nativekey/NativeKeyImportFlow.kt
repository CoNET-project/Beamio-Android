package com.beamio.app.nativekey

import androidx.annotation.StringRes
import com.beamio.app.R
import java.lang.ref.WeakReference

/** Import modes (spec 25.26.3). The native page switches between them; the PWA never chooses. */
enum class ImportMode { PRIVATE_KEY, MNEMONIC }

/** What the page does with a result. Kept apart from the view so it can be tested without a device. */
object NativeKeyImportFlow {
    /** Runs one import. The caller has already cleared the input box; [raw] is not kept. */
    fun submit(mode: ImportMode, raw: String, backend: NativeKeyBackend = NativeKeyBackends.current): ImportCode =
        when (mode) {
            ImportMode.PRIVATE_KEY -> backend.importPrivateKey(raw)
            ImportMode.MNEMONIC -> backend.importMnemonic(raw)
        }

    /**
     * The message for a result (spec 25.25.5 keys imp.err.*, as imp_err_*; texts are drafts pending P-IMP-COPY). `null` for [ImportCode.CANCELLED]:
     * no message, back to the previous page. No message contains the input, its length or the derived address.
     */
    @StringRes
    fun messageRes(code: ImportCode): Int? = when (code) {
        ImportCode.OK -> R.string.native_key_import_ok
        ImportCode.INVALID_FORMAT -> R.string.imp_err_format
        ImportCode.INVALID_KEY -> R.string.imp_err_range
        ImportCode.INVALID_MNEMONIC -> R.string.imp_err_mnemonic
        ImportCode.ADDRESS_MISMATCH -> R.string.imp_err_mismatch
        ImportCode.ALREADY_EXISTS -> R.string.imp_err_exists
        ImportCode.WRITE_FAILED -> R.string.imp_err_write
        ImportCode.READBACK_FAILED -> R.string.imp_err_readback
        ImportCode.NOT_SUPPORTED -> R.string.imp_err_not_supported
        ImportCode.CANCELLED -> null
    }

    /** After these results the page closes on its own and the web page is reloaded to check again. */
    fun closesAndReloads(code: ImportCode): Boolean = code == ImportCode.OK || code == ImportCode.ALREADY_EXISTS

    fun closeDelayMs(code: ImportCode): Long = if (code == ImportCode.OK) 800L else 1200L

    /** Whether `nativeImportOpen` should show the page: only when the device has no key (or it is not known). */
    fun shouldOpen(backend: NativeKeyBackend = NativeKeyBackends.current): Boolean = backend.hasKey() != true
}

/**
 * Connects the SDK's `NativeImportHost.launcher` to the activity on screen. MainActivity registers itself in
 * onCreate and clears itself in onDestroy; a relaunched activity replaces the old one.
 */
object NativeKeyImportRoute {
    private var opener: WeakReference<() -> Boolean>? = null

    @Synchronized
    fun register(open: () -> Boolean) {
        opener = WeakReference(open)
    }

    @Synchronized
    fun unregister(open: () -> Boolean) {
        if (opener?.get() === open) opener = null
    }

    /** Called by the SDK launcher. `true` when the page was (or is being) shown. */
    fun open(): Boolean {
        if (!NativeKeyImportFlow.shouldOpen()) return false
        val o = synchronized(this) { opener?.get() } ?: return false
        return o()
    }
}
