package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Spec §25.52HD (HD.1–HD.3, PM R2088): the debugqa build type is the approved S25 QA build and declares nothing itself. */
class DebugqaBuildTypeTest {
    private val g = File("build.gradle.kts").readText()

    @Test
    fun debugqaIsT168DebugKeyAndLabelled() {
        assertTrue(g.contains("create(\"debugqa\") {"))
        assertTrue(g.contains("onVariants(selector().withBuildType(\"debugqa\")) { variant -> variant.applicationId.set(\"com.beamio.app.t168\") }"))
        val block = g.substringAfter("create(\"debugqa\") {").substringBefore("\n        }")
        assertTrue(block.contains("signingConfig = signingConfigs.getByName(\"debug\")"))
        assertFalse(block.contains("signingConfigs.getByName(\"release\")"))
        assertTrue(block.contains("versionNameSuffix = \"-debugqa\""))
        assertTrue(block.contains("buildConfigField(\"String\", \"QA_BUILD_LABEL\", \"\\\"debugqa\\\"\")"))
    }

    @Test
    fun debugqaIsKeptOutOfReleaseAndStoreAndOutOfT168r() {
        assertTrue(g.contains("-PqaReleaseVariant (t168r) cannot build it."))
        assertTrue(g.contains("\"packageRelease\", \"packageReleaseBundle\", \"signReleaseBundle\", \"packageStore\", \"packageStoreBundle\", \"signStoreBundle\""))
        assertTrue(g.contains("dependsOn(verifyDebugqaNotInReleaseOrStore)"))
    }

    /** Reviewer on f1cac906: debugqa uses debug's code/manifest/NSC but refuses the two debug-only add-ons explicitly. */
    @Test
    fun debugqaRefusesTheDebugOnlyAddOns() {
        assertTrue(g.contains("if ((otaLocalStub || chatQaHooks) && gradle.startParameter.taskNames.any { it.contains(\"debugqa\", ignoreCase = true) }) {"))
        val ss = g.substringAfter("maybeCreate(\"debugqa\").let {").substringBefore("\n        }")
        assertTrue(ss.contains("listOf(\"src/debug/java\", \"src/ota/java\")"))
        assertTrue(ss.contains("it.manifest.srcFile(\"src/debug/AndroidManifest.xml\")"))
        assertFalse(ss.contains("otaLocalStub")); assertFalse(ss.contains("qaHooks"))
    }

    /** PM R2102 (R2099 gap): the legacy sensitive bridge is off by default in every build type, debug and debugqa included. */
    @Test
    fun legacySensitiveBridgeIsOffByDefaultEverywhere() {
        assertTrue(g.contains("val legacyDebug = legacySensitiveBridgeProp == \"true\""))
        assertTrue(g.contains("val legacyRelease = legacySensitiveBridgeProp == \"true\""))
        assertFalse(g.contains("legacySensitiveBridgeProp != \"false\""))
        // this unit-test build was made without -PlegacySensitiveBridge
        assertFalse(com.beamio.app.BuildConfig.LEGACY_SENSITIVE_BRIDGE)
    }

    /** HD.3 item 1: no capability is declared by the shell (no shell constant, no QA switch). */
    @Test
    fun shellNeverDeclaresNativeKeys() {
        // Source sets that ship in an APK (tests such as androidTest only read hello and are excluded).
        val shipped = File("src").listFiles()!!.filter { it.isDirectory && !it.name.startsWith("test") && it.name != "androidTest" }
        val main = shipped.asSequence().flatMap { it.walkTopDown() }.filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
        assertFalse(main.any { it.readText().contains("identity.native-keys.v1") })
        assertFalse(g.contains("identity.native-keys.v1"))
    }
}
