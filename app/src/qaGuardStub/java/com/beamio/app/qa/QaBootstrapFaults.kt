package com.beamio.app.qa

import android.content.Context
import java.io.InputStream

/** Release and store: no QA fault injection (the debug source set has the real one). */
object QaBootstrapFaults {
    @Suppress("UNUSED_PARAMETER")
    fun wrapBundledZip(context: Context, open: () -> InputStream): () -> InputStream = open
}
