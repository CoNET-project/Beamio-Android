package com.beamio.app.nativekey

import android.text.InputType
import android.view.inputmethod.EditorInfo
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Shell side of the native import (spec 25.25, 25.26.3) and the shell gate (25.26.4b, T-161). No device needed. */
class NativeKeyImportTest {
    private class FakeBackend(private val key: Boolean?, private val result: ImportCode = ImportCode.OK) : NativeKeyBackend {
        val calls = mutableListOf<String>()
        override fun hasKey(): Boolean? = key
        override fun importPrivateKey(raw: String): ImportCode { calls += "key"; return result }
        override fun importMnemonic(raw: String): ImportCode { calls += "mnemonic"; return result }
    }

    @After
    fun reset() {
        NativeKeyBackends.current = NativeKeyBackend.Unavailable
    }

    // --- shell gate --------------------------------------------------------------------------------------------

    private val pmList = listOf(
        "prepareSystemCall", "cancelPreparedSystemCall", "startSystemCall", "reportIncomingSystemCall", "endSystemCall",
        "clearOfflineChatAlerts", "notifyBackgroundChat", "postPgpCiphertext", // setNativeChatPgpSecrets removed
        "setNativeVoiceRelayNodes", "setNativeSiNodeRoster", "chatModuleSignResponse", "bindPushIdentity",
        "registerPushDeviceHttp", "saveRecoveryQrToPhotos", "scanRecoveryQr",
        // (2026-11-14): call-related entries added to the gate
        "notifyVoiceMicReady", "queryIncomingCallOutcome", "startNativeVoiceMic", "cacheCallerAvatars",
    )
    // scanRecoveryQr: removed from the Android shell (spec r3fr §25.52DR.4)
    private val absentOnAndroid = setOf("registerPushDeviceHttp", "saveRecoveryQrToPhotos", "scanRecoveryQr")

    @Test
    fun gateCoversThePmListThatExistsOnAndroid() {
        assertEquals(pmList.filterNot { it in absentOnAndroid }.toSet(), ShellNoKeyGate.GATED)
        println("EVIDENCE gate-list gated=${ShellNoKeyGate.GATED.size} absentOnAndroid=$absentOnAndroid")
    }

    @Test
    fun g0AnswersNoKeyForEveryGatedEntry() {
        val g0 = FakeBackend(key = false)
        for (e in ShellNoKeyGate.GATED) assertEquals(e, "no_key", ShellNoKeyGate.answer(e, g0))
    }

    @Test
    fun withAKeyOrWithoutSdkSupportNothingIsGated() {
        for (b in listOf(FakeBackend(key = true), FakeBackend(key = null), NativeKeyBackend.Unavailable)) {
            for (e in ShellNoKeyGate.GATED) assertNull(e, ShellNoKeyGate.answer(e, b))
        }
    }

    @Test
    fun entriesOutsideTheListAreNeverGated() {
        val g0 = FakeBackend(key = false)
        for (e in listOf("openURL", "saveFile", "scanQr", "startPhysicalCardBind", "chatModuleCommand", "publishAppState", "unknownEntry")) {
            assertNull(e, ShellNoKeyGate.answer(e, g0))
        }
    }

    /** Each gated entry exists in MainActivity and checks the gate as its first statement, before reading its argument. */
    @Test
    fun everyGatedEntryChecksTheGateFirst() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        for (e in ShellNoKeyGate.GATED) {
            // the sensitive entries are plain `open fun` on the base bridge (reached via window.BeamioShell / the legacy subclass).
            val m = Regex("(?:@JavascriptInterface\\s+fun|open fun) $e\\([^)]*\\)[^{\\n]*\\{\\n([^\\n]*)\\n").find(src)
            checkNotNull(m) { "no bridge entry $e" }
            // Boolean entries (startNativeVoiceMic) return false; the others return Unit.
            val first = m.groupValues[1].trim()
            assertTrue(e, first == "if (shellNoKey(\"$e\")) return" || first == "if (shellNoKey(\"$e\")) return false")
        }
        println("EVIDENCE gate-first-statement entries=${ShellNoKeyGate.GATED.size}")
    }

    // --- import flow -------------------------------------------------------------------------------------------

    @Test
    fun submitRoutesByModeOnly() {
        val b = FakeBackend(key = false)
        NativeKeyImportFlow.submit(ImportMode.PRIVATE_KEY, "x", b)
        NativeKeyImportFlow.submit(ImportMode.MNEMONIC, "y", b)
        assertEquals(listOf("key", "mnemonic"), b.calls)
    }

    @Test
    fun everyResultHasItsMessageAndCancelHasNone() {
        for (c in ImportCode.entries) {
            if (c == ImportCode.CANCELLED) assertNull(NativeKeyImportFlow.messageRes(c))
            else assertTrue(c.name, NativeKeyImportFlow.messageRes(c) != null)
        }
        assertTrue(NativeKeyImportFlow.closesAndReloads(ImportCode.OK))
        assertTrue(NativeKeyImportFlow.closesAndReloads(ImportCode.ALREADY_EXISTS))
        for (c in ImportCode.entries - setOf(ImportCode.OK, ImportCode.ALREADY_EXISTS)) {
            assertFalse(c.name, NativeKeyImportFlow.closesAndReloads(c))
        }
    }

    @Test
    fun sdkWireCodesMapAndUnknownIsAFailure() {
        for (w in listOf("ok", "invalid_format", "invalid_key", "invalid_mnemonic", "address_mismatch", "already_exists",
            "write_failed", "readback_failed", "cancelled")) {
            assertEquals(w, ImportCode.fromWire(w).wire)
        }
        assertEquals(ImportCode.WRITE_FAILED, ImportCode.fromWire("something_new"))
    }

    /** Messages are fixed texts: no placeholder can carry the input, its length or an address (25.25.5). */
    @Test
    fun messagesHaveNoPlaceholdersInBothLanguages() {
        for (f in listOf("src/main/res/values/strings.xml", "src/main/res/values-zh/strings.xml")) {
            val lines = File(f).readLines().filter { it.contains("name=\"native_key_import_") || it.contains("name=\"imp_err_") }
            assertEquals(f, 17, lines.size)
            for (l in lines) assertFalse(l, Regex("%[0-9$]*[sd]").containsMatchIn(l))
        }
    }

    /** Spec 25.25.5 / 25.26.3 keys (imp.err.*) each have a resource imp_err_* in both languages. */
    @Test
    fun failureKeysFollowTheSpec() {
        val keys = listOf("format", "range", "mnemonic", "mismatch", "exists", "write", "readback")
        for (f in listOf("src/main/res/values/strings.xml", "src/main/res/values-zh/strings.xml")) {
            val text = File(f).readText()
            for (k in keys) assertTrue("$f imp_err_$k", text.contains("name=\"imp_err_$k\""))
        }
        assertEquals(com.beamio.app.R.string.imp_err_readback, NativeKeyImportFlow.messageRes(ImportCode.READBACK_FAILED))
        assertEquals(com.beamio.app.R.string.imp_err_write, NativeKeyImportFlow.messageRes(ImportCode.WRITE_FAILED))
    }

    /** Default build (chat SDK 0.2.6): the page can open, a submit answers not_supported, never success. */
    @Test
    fun emptyBackendNeverSucceedsSilently() {
        val b = NativeKeyBackend.Unavailable
        for (m in ImportMode.entries) {
            val code = NativeKeyImportFlow.submit(m, "anything", b)
            assertEquals(ImportCode.NOT_SUPPORTED, code)
            assertEquals("not_supported", code.wire)
            assertFalse(NativeKeyImportFlow.closesAndReloads(code))
            assertEquals(com.beamio.app.R.string.imp_err_not_supported, NativeKeyImportFlow.messageRes(code))
        }
        assertTrue("page may open without SDK support", NativeKeyImportFlow.shouldOpen(b))
        assertNull("gate passes through without SDK support", ShellNoKeyGate.answer("postPgpCiphertext", b))
        println("EVIDENCE empty-backend submit=not_supported closes=false shouldOpen=true")
    }

    @Test
    fun clipboardIsClearedOnlyWhenItHoldsTheSubmittedText() {
        assertTrue(NativeKeyImportActivity.shouldClearClipboard("  abc  ", "abc"))
        assertFalse(NativeKeyImportActivity.shouldClearClipboard("something else", "abc"))
        assertFalse(NativeKeyImportActivity.shouldClearClipboard(null, "abc"))
        assertFalse(NativeKeyImportActivity.shouldClearClipboard("", ""))
    }

    // --- open route --------------------------------------------------------------------------------------------

    @Test
    fun openShowsThePageOnlyWithoutAKey() {
        var opened = 0
        val opener: () -> Boolean = { opened++; true }
        NativeKeyImportRoute.register(opener)
        try {
            NativeKeyBackends.current = FakeBackend(key = false)
            assertTrue(NativeKeyImportRoute.open())
            NativeKeyBackends.current = FakeBackend(key = true)
            assertFalse(NativeKeyImportRoute.open())
            assertEquals(1, opened)
        } finally {
            NativeKeyImportRoute.unregister(opener)
        }
        NativeKeyBackends.current = FakeBackend(key = false)
        assertFalse("no activity registered", NativeKeyImportRoute.open())
    }

    @Test
    fun unregisterOnlyRemovesTheSameOpener() {
        val a: () -> Boolean = { true }
        val b: () -> Boolean = { true }
        NativeKeyBackends.current = FakeBackend(key = false)
        NativeKeyImportRoute.register(a)
        NativeKeyImportRoute.register(b) // relaunched activity replaces the old one
        NativeKeyImportRoute.unregister(a) // old activity's onDestroy must not clear the new one
        try {
            assertTrue(NativeKeyImportRoute.open())
        } finally {
            NativeKeyImportRoute.unregister(b)
        }
    }

    // --- secure input ------------------------------------------------------------------------------------------

    @Test
    fun secureInputHasNoSuggestionsOrLearning() {
        for (m in ImportMode.entries) {
            val t = NativeKeyImportActivity.inputTypeFor(m)
            assertTrue(m.name, t and InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS != 0)
            // Both modes masked: a visible field would put the text into accessibility events and nodes.
            assertEquals(m.name, InputType.TYPE_TEXT_VARIATION_PASSWORD, t and InputType.TYPE_MASK_VARIATION)
        }
        assertEquals(InputType.TYPE_TEXT_VARIATION_PASSWORD,
            NativeKeyImportActivity.inputTypeFor(ImportMode.PRIVATE_KEY) and InputType.TYPE_MASK_VARIATION)
        assertTrue(NativeKeyImportActivity.IME_OPTIONS and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
    }
}
