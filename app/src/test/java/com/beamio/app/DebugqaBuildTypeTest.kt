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
