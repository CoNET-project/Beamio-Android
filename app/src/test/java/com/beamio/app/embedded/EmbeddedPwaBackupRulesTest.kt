package com.beamio.app.embedded

import org.junit.Assert.assertEquals
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * The PWA bundle directory (files/silentpass_pwa/, rebuilt from the embedded ZIP) is excluded from Auto Backup and from
 * device transfer; the three chat key preferences stay excluded; since 192 the WebView data directory (app_webview/), the native
 * vault directory (native_wallet_v1/) and the account PGP store too. The local chat history (conet-chat) is deliberately not excluded.
 * Every rule set must list exactly these exclusions.
 */
class EmbeddedPwaBackupRulesTest {
    private val expected = setOf(
        "sharedpref:beamio_chat_wallet_v1.xml",
        "sharedpref:beamio_chat_pgp_v1.xml",
        "sharedpref:beamio_chat_pgp_plain_v1.xml",
        "file:${EmbeddedPwaConstants.ROOT_DIR_NAME}/",
        // 192 (plan E6): the WebView data directory (page IndexedDB / localStorage) is never backed up or transferred
        "root:app_webview/",
        // 192: Keystore-wrapped stores; their keys never leave the device, so a restored copy could not be opened
        "file:native_wallet_v1/",
        "sharedpref:beamio_sdk_account_pgp_k_v1.xml",
    )

    private fun res(name: String): File =
        listOf(File("src/main/res/xml/$name"), File("app/src/main/res/xml/$name")).first { it.isFile }

    private fun excludes(parent: Element): Set<String> {
        val nodes = parent.getElementsByTagName("exclude")
        return (0 until nodes.length).map { nodes.item(it) as Element }.map { "${it.getAttribute("domain")}:${it.getAttribute("path")}" }.toSet()
    }

    private fun doc(name: String) = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(res(name)).documentElement

    @Test
    fun fullBackupExcludesPwaDirectoryAndChatKeys() {
        val root = doc("backup_rules.xml")
        assertEquals("full-backup-content", root.tagName)
        assertEquals(expected, excludes(root))
        assertEquals(0, root.getElementsByTagName("include").length)
    }

    @Test
    fun cloudBackupAndDeviceTransferExcludePwaDirectoryAndChatKeys() {
        val root = doc("data_extraction_rules.xml")
        for (section in listOf("cloud-backup", "device-transfer")) {
            val nodes = root.getElementsByTagName(section)
            assertEquals(section, 1, nodes.length)
            val el = nodes.item(0) as Element
            assertEquals(section, expected, excludes(el))
            assertEquals(section, 0, el.getElementsByTagName("include").length)
        }
    }

    /** 192: the chat history is keyed from the account key (HKDF), not from Keystore, so it stays in backup and transfer. */
    @Test
    fun chatHistoryIsNotExcluded() {
        for (name in listOf("backup_rules.xml", "data_extraction_rules.xml")) {
            val root = doc(name)
            val sections = listOf(root) + listOf("cloud-backup", "device-transfer").mapNotNull { root.getElementsByTagName(it).item(0) as? Element }
            for (el in sections) assertEquals(name, false, excludes(el).any { it.contains("conet-chat") })
        }
    }

    @Test
    fun manifestUsesTheseRuleFiles() {
        val m = listOf(File("src/main/AndroidManifest.xml"), File("app/src/main/AndroidManifest.xml")).first { it.isFile }.readText()
        assert(m.contains("android:dataExtractionRules=\"@xml/data_extraction_rules\""))
        assert(m.contains("android:fullBackupContent=\"@xml/backup_rules\""))
    }
}
