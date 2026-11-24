package com.beamio.app.embedded

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The manifest v2 golden vectors on a device below API 33 (no JDK Ed25519 there; the shell verifies with
 * BouncyCastle) with the platform org.json. The TEST ONLY vectors are copied into the app's files/otavectors/ by the
 * tester (run-as), never packaged: vectors.json, zips/, golden/SilentPassUI-0.53.48.zip.
 */
@RunWith(AndroidJUnit4::class)
class OtaVectorsInstrumentedTest {
    @Test
    fun goldenVectorsOnDevice() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(ctx.filesDir, "otavectors")
        assumeTrue("copy the vectors into files/otavectors first", File(dir, "vectors.json").isFile)
        val work = File(ctx.cacheDir, "otavectors-work").apply { deleteRecursively(); mkdirs() }
        val r = OtaVectorRunner(dir, File(dir, "golden/SilentPassUI-0.53.48.zip"), work)
        val sha = OtaTestShared.sha256(File(dir, "vectors.json").readBytes())
        val outcomes = r.runAll()
        outcomes.forEach { Log.i(TAG, "vector $it") }
        val nonCanonicalS = r.nonCanonicalS()
        val digest = r.goldenContentDigest()
        Log.i(TAG, "api=${Build.VERSION.SDK_INT} vectors.json=$sha cases=${outcomes.size} passed=${outcomes.count { it.ok }} nonCanonicalS=$nonCanonicalS goldenDigest=$digest")
        work.deleteRecursively()
        assertEquals("747abad22e97da707d45684ec6078fc0abab354405dc7cf228b6d8a4538b8031", sha)
        assertEquals(45, outcomes.size)
        assertTrue("failed: ${outcomes.filter { !it.ok }}", outcomes.all { it.ok })
        assertEquals("bad_signature", nonCanonicalS)
        assertEquals("13080eef9cec6068692696a8bd70ff10d19c1cfd9aa815f7c421f24748604974", digest)
    }

    private companion object {
        const val TAG = "OtaVectorsQ1"
    }
}
