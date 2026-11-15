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
     * The SDK binding registers the create page as NativeAccountCreateHost.launcher (its own route, never import or
     * recovery), confirms through NativeAccountCreate.confirm and closes through pageClosed. The page has no input
     * field, is FLAG_SECURE, does not log, and does not build result events itself (the SDK sends them).
     */
    @Test
    fun createPageIsItsOwnSecureRouteAndTheSdkSendsTheResult() {
        val binding = File("src/nativekeySdk/java/com/beamio/app/nativekey/NativeKeySdkBinding.kt").readText()
        assertTrue(binding.contains("NativeAccountCreateHost.launcher = { NativeAccountCreateRoute.open() }"))
        assertTrue(binding.contains("NativeAccountCreate.confirm(app)"))
        assertTrue(binding.contains("NativeAccountCreateHost.pageClosed()"))
        assertFalse(binding.contains("NativeAccountCreateHost.report("))
        assertFalse(Regex("NativeAccountCreateHost\\.launcher[^\\n]*(Import|Recovery)").containsMatchIn(binding))
        val page = File("src/main/java/com/beamio/app/nativekey/NativeAccountCreateActivity.kt").readText()
        assertTrue(page.contains("FLAG_SECURE"))
        assertTrue(page.contains("pageClosed()"))
        assertFalse(page.contains("EditText"))
        assertFalse(page.contains("Log."))
        assertFalse(page.contains("nativeAccountCreateResult") || page.contains("evaluateJavascript"))
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("NativeAccountCreateRoute.register(nativeAccountCreateOpener)"))
        assertTrue(main.contains("NativeAccountCreateRoute.unregister(nativeAccountCreateOpener)"))
    }
}
