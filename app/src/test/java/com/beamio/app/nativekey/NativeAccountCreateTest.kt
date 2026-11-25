package com.beamio.app.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class NativeAccountCreateTest {
    @Test
    fun codesMatchTheSdkList() {
        assertEquals(
            listOf("ok", "cancelled", "already_exists", "write_failed", "readback_failed"),
            CreateCode.values().map { it.wire },
        )
        for (c in CreateCode.values()) assertEquals(c, CreateCode.fromWire(c.wire))
        assertEquals(CreateCode.WRITE_FAILED, CreateCode.fromWire("something_new"))
    }

    @Test
    fun routeDoesNotOpenWithoutAnEngine() {
        val before = NativeAccountCreateBackends.current
        try {
            NativeAccountCreateBackends.current = NativeAccountCreateBackend.Unavailable
            var opened = false
            val o: () -> Boolean = { opened = true; true }
            NativeAccountCreateRoute.register(o)
            assertFalse(NativeAccountCreateRoute.open())
            assertFalse(opened)
            NativeAccountCreateRoute.unregister(o)
        } finally {
            NativeAccountCreateBackends.current = before
        }
    }

    @Test
    fun routeOpensThroughTheRegisteredOpenerWhenTheEngineIsThere() {
        val before = NativeAccountCreateBackends.current
        try {
            NativeAccountCreateBackends.current = object : NativeAccountCreateBackend {
                override val supported = true
                override fun confirm(done: (CreateCode) -> Unit) = done(CreateCode.OK)
            }
            assertFalse("no page registered", NativeAccountCreateRoute.open())
            var opened = 0
            val o: () -> Boolean = { opened++; true }
            NativeAccountCreateRoute.register(o)
            assertTrue(NativeAccountCreateRoute.open())
            assertEquals(1, opened)
            NativeAccountCreateRoute.unregister(o)
            assertFalse(NativeAccountCreateRoute.open())
        } finally {
            NativeAccountCreateBackends.current = before
        }
    }

    /**
     * 193 (r3si item 63): the SDK binding still registers NativeAccountCreateHost.launcher (its own route, never import or recovery) and
     * confirms through NativeAccountCreate.confirm; the shell's opener is headless (no activity, no manifest entry, no native_create_ strings).
     */
    @Test
    fun createRouteIsHeadlessAndTheSdkSendsTheResult() {
        val binding = File("src/nativekeySdk/java/com/beamio/app/nativekey/NativeKeySdkBinding.kt").readText()
        assertTrue(binding.contains("NativeAccountCreateHost.launcher = { NativeAccountCreateRoute.open() }"))
        assertTrue(binding.contains("NativeAccountCreate.confirm(app)"))
        assertFalse(binding.contains("NativeAccountCreateHost.report("))
        assertFalse(Regex("NativeAccountCreateHost\\.launcher[^\\n]*(Import|Recovery)").containsMatchIn(binding))
        assertFalse(File("src/main/java/com/beamio/app/nativekey/NativeAccountCreateActivity.kt").exists())
        assertFalse(File("src/main/AndroidManifest.xml").readText().contains("NativeAccountCreateActivity"))
        for (res in listOf("src/main/res/values/strings.xml", "src/main/res/values-zh/strings.xml")) {
            assertFalse(res, File(res).readText().contains("native_create_"))
        }
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("NativeAccountCreateRoute.register(nativeAccountCreateOpener)"))
        assertTrue(main.contains("NativeAccountCreateRoute.unregister(nativeAccountCreateOpener)"))
        val opener = main.substring(main.indexOf("private val nativeAccountCreateOpener")).take(500)
        assertTrue(opener.contains("NativeAccountCreateBackends.current.confirm"))
        assertFalse(opener.contains("startActivity"))
    }
}
