package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 *spec r3dk §25.52BM.1 and CRED: no shell answer carries a recovery code, and scanRecoveryQr refuses
 * before any scan. listInstalledWalletApps is an alias of queryInstalledApps (§25.52BD.1).
 */
class RecoveryCodeNotOnBridgeTest {
    private val roots = listOf("src/main/java", "src/nativekeySdk/java", "src/nativekeyNone/java", "src/ota/java", "src/noota/java")

    @Test
    fun noShellSourcePutsARecoveryCodeIntoAnAnswer() {
        val files = roots.map { File(it) }.filter { it.isDirectory }.flatMap { d -> d.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
        assertTrue(files.isNotEmpty())
        for (f in files) {
            val src = f.readText()
            assertFalse(f.path, src.contains("\"recoveryCode\""))
        }
    }

    @Test
    fun scanRecoveryQrIsGone() {
        // removed from the shell entirely (no bridge entry, no BeamioShell action, no scanner path).
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertFalse(Regex("fun scanRecoveryQr\\(").containsMatchIn(src))
        assertFalse(src.contains("bridgeAction = \"scanRecoveryQr\""))
    }

    @Test
    fun listInstalledWalletAppsDelegatesToQueryInstalledApps() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(src.contains("fun listInstalledWalletApps(): String = queryInstalledApps(\"{}\")"))
        assertTrue(src.contains("fun listInstalledWalletApps(json: String): String = queryInstalledApps(json)"))
        assertEquals(1, Regex("fun legacyInstalledWalletIds\\(").findAll(src).count())
    }
}
