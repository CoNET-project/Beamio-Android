package com.beamio.app

import com.beamio.app.qa.QaWriteGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Release build shape (spec r3cx §25.52AZ.4, r3de §25.52BF.2, r3dg §25.52BI.1). Runs only in
 * `testReleaseUnitTest`, against the release variant's classes before R8.
 */
class ReleaseBuildShapeTest {
    private fun absent(name: String) {
        try {
            Class.forName(name)
            fail("$name must not be in the release build")
        } catch (_: ClassNotFoundException) {
        }
    }

    @Test
    fun planNChannelIsOnAndThisIsARelease() {
        assertFalse(BuildConfig.DEBUG)
        assertTrue("window.BeamioShellRecord is injected in release (PLAN_N)", BuildConfig.PLAN_N)
        assertFalse(BuildConfig.QA_WRITE_GUARD)
    }

    /** (d), spec §25.52DR.3: release and store build without the legacy sensitive bridge by default. */
    @Test
    fun legacySensitiveBridgeIsOffAndTheBaseBridgeHasOnly13Methods() {
        assertFalse("release/store must not re-expose sensitive methods on CashTreesAndroid", BuildConfig.LEGACY_SENSITIVE_BRIDGE)
        // applyEmbeddedPwaUpdate answers ota_disabled unless REMOTE_PWA_UPDATE (internal OTA test builds only).
        assertFalse("this release build has no remote PWA update", BuildConfig.REMOTE_PWA_UPDATE)
        val base = Class.forName("com.beamio.app.MainActivity\$CashTreesJsBridge")
        val exposed = base.methods.filter { it.isAnnotationPresent(android.webkit.JavascriptInterface::class.java) }.map { it.name }.toSortedSet()
        assertEquals(
            sortedSetOf(
                "applyEmbeddedPwaUpdate", "getNfcStatus", "requestDeliveryHealth", "openDeliverySettings", "dismissDeliveryHealthNotice",
                "getEmbeddedPwaVersion", "getEmbeddedPwaPendingVersion", "publishAppState", "clearOfflineChatAlerts",
                "notifyBackgroundChat", "debugLog", "chatModuleAvailable", "chatModuleIsRunning",
            ),
            exposed,
        )
    }

    /**: the bundle-store test hook is not in the release classes (it lives in the test source set). */
    @Test
    fun bundleStoreHasNoTestHook() {
        val c = com.beamio.app.embedded.EmbeddedPwaBundleStore::class.java
        val names = c.declaredMethods.map { it.name } + c.declaredFields.map { it.name }
        assertFalse(names.toString(), names.any { it.contains("afterStoreReplaceForTest") })
    }

    @Test
    fun qaGuardIsTheNoOpStub() {
        assertFalse(QaWriteGuard.isActive)
        assertTrue(QaWriteGuard.sdkCommandAllowed("anything"))
        assertTrue(QaWriteGuard.nativeWriteAllowed("voice-post", "203.0.113.1"))
        // The stub has none of the debug guard's members (host list, page script, JS interface).
        val names = QaWriteGuard::class.java.declaredMethods.map { it.name }.toSet() + QaWriteGuard::class.java.declaredFields.map { it.name }
        for (n in listOf("pageScript", "withWorkerPrelude", "registerAllowance", "RPC_HOSTS", "WORKER_PRELUDE", "JS_NAME")) {
            assertFalse(n, n in names)
        }
        assertEquals(0, QaWriteGuard::class.java.declaredClasses.size)
    }

    @Test
    fun referenceAndQaClassesAreNotCompiledIn() {
        absent("com.beamio.app.legacy.ShellRecordBridge")
        absent("com.beamio.app.legacy.ShellRecordStore")
        absent("com.beamio.app.legacy.ShellRecordRules")
        absent("com.beamio.app.legacy.RecordCipher")
        absent("com.beamio.app.qa.hooks.QaNativeEvidenceActivity")
        absent("com.beamio.app.qa.QaWriteGuard\$JsIface")
    }

    @Test
    fun planNClassesThatReleaseNeedsArePresent() {
        Class.forName("com.beamio.app.legacy.ShellRecordChannel")
        Class.forName("com.beamio.app.legacy.ShellRecordInit")
        Class.forName("com.beamio.app.legacy.ShellRecordState")
        Class.forName("com.beamio.app.legacy.LegacyPwaStore")
    }

    @Test
    fun removedBridgeEntriesAreGone() {
        val methods = MainActivity::class.java.declaredClasses.flatMap { c -> c.declaredMethods.map { it.name } }.toSet()
        for (n in listOf("setNativeChatPgpSecrets", "requestPendingSystemCallAction")) assertFalse(n, n in methods)
        assertTrue("debugLog stays for old pages", "debugLog" in methods)
    }
}
