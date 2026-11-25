package com.beamio.app.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * r3sc R6: secure only on a confirmed G0. 192 AVD finding (2026-11-25): a signed-in account held only in the two-state store
 * (vault without a key) got FLAG_SECURE when the guard looked at the vault alone; it must not.
 */
class OnboardingScreenGuardTest {
    @Test
    fun securesOnlyWhenVaultStoreAndSessionAllSayNoAccount() {
        assertTrue(OnboardingScreenGuard.secure(vaultHasKey = false, storeEntries = 0, sessionReady = false))
        assertTrue(OnboardingScreenGuard.secure(vaultHasKey = false, storeEntries = 0, sessionReady = null))
        // store-only account (the r2271-upg case): not secured
        assertFalse(OnboardingScreenGuard.secure(vaultHasKey = false, storeEntries = 2, sessionReady = false))
        assertFalse(OnboardingScreenGuard.secure(vaultHasKey = true, storeEntries = 0, sessionReady = false))
        assertFalse(OnboardingScreenGuard.secure(vaultHasKey = false, storeEntries = 0, sessionReady = true))
        // anything unknown never secures
        assertFalse(OnboardingScreenGuard.secure(vaultHasKey = null, storeEntries = 0, sessionReady = false))
        assertFalse(OnboardingScreenGuard.secure(vaultHasKey = false, storeEntries = null, sessionReady = false))
    }

    @Test
    fun storeEntriesCountsPresenceOnly() {
        val root = Files.createTempDirectory("guard").toFile()
        try {
            assertEquals(0, OnboardingScreenGuard.storeEntries(root))
            val dir = File(root, OnboardingScreenGuard.STORE_DIR).apply { mkdirs() }
            assertEquals(0, OnboardingScreenGuard.storeEntries(root))
            File(dir, "current.v1").writeText("x")
            assertEquals(1, OnboardingScreenGuard.storeEntries(root))
            // a plain file where the directory should be cannot be listed: unknown
            dir.deleteRecursively(); File(root, OnboardingScreenGuard.STORE_DIR).writeText("x")
            assertNull(OnboardingScreenGuard.storeEntries(root))
        } finally {
            root.deleteRecursively()
        }
    }
}
