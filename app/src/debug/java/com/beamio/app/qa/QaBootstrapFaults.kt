package com.beamio.app.qa

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException
import java.io.InputStream

/**
 * QA only (debug source set; release and store compile the no-op in src/qaGuardStub). isolated acceptance:
 * when the app-private flag file `files/beamio-qa-fault-bundled-zip` exists (created only with `run-as` on a debuggable QA
 * build), reading the bundled SilentPassUI.zip throws, so the bootstrap's unreadable-zip paths can be checked on an emulator.
 * Nothing else changes; the flag is never created by the app.
 */
object QaBootstrapFaults {
    const val FLAG = "beamio-qa-fault-bundled-zip"

    fun wrapBundledZip(context: Context, open: () -> InputStream): () -> InputStream {
        val flag = File(context.applicationContext.filesDir, FLAG)
        return {
            if (flag.isFile) {
                Log.w("BeamioEmbeddedPwa", "QA fault: bundled SilentPassUI.zip read fails (flag present)")
                throw IOException("QA fault: bundled zip read")
            }
            open()
        }
    }
}
