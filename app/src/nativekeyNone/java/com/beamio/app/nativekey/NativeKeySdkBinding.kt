package com.beamio.app.nativekey

import android.content.Context

/**
 * Default build (chat SDK 0.2.6): the SDK has no native key import host. The backend stays
 * [NativeKeyBackend.Unavailable], the shell gate passes everything through and `nativeImportOpen` is not handled.
 */
object NativeKeySdkBinding {
    const val ENABLED = false

    fun install(@Suppress("UNUSED_PARAMETER") context: Context) = Unit
}
