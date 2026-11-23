package com.beamio.app.legacy

import network.conet.chat.nativekey.LegacyStoreReport
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** The report value for the old origin directory: absent without it, unreadable with it, never found (synthetic folders only). */
class LegacyStoreReportShellTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun noOldOriginDirectoryIsAbsent() {
        val root = tmp.newFolder("app_webview")
        File(root, "Default/IndexedDB/https_appassets.androidplatform.net_0.indexeddb.leveldb").mkdirs()
        assertEquals(LegacyStoreReport.ABSENT, LegacyStoreReportShell.valueFor(root))
    }

    @Test
    fun oldOriginDirectoryIsUnreadableNeverFound() {
        val root = tmp.newFolder("app_webview")
        File(root, "Default/IndexedDB/${LegacyStoreReportShell.OLD_ORIGIN_DIR}").mkdirs()
        assertEquals(LegacyStoreReport.UNREADABLE, LegacyStoreReportShell.valueFor(root))
    }

    @Test
    fun emptyWebViewFolderIsAbsent() {
        assertEquals(LegacyStoreReport.ABSENT, LegacyStoreReportShell.valueFor(tmp.newFolder("empty")))
    }
}
