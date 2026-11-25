package com.beamio.app.nativekey

import java.io.File

/**
 * Spec r3sc R6 (plan E5): FLAG_SECURE only while the device has no native account at all (G0: onboarding and the recovery on the PWA
 * page). An account may live in the vault or only in the SDK's two-state mnemonic store (no_backup/mnemonic_sets_v1, the store-primary
 * rule), so the vault alone is not enough: a signed-in store account must keep normal screenshots. The window is secured only when
 * all three are confirmed: the vault has no key, the store directory is absent or empty, and the native session is not ready.
 * Anything unknown leaves the window unsecured (the guard never hides a signed-in user's screen on a guess).
 */
object OnboardingScreenGuard {
    /** The SDK's store directory name (chat SDK 0.2.30 MnemonicSetStore.DIRECTORY); read for presence only, never opened. */
    const val STORE_DIR = "mnemonic_sets_v1"

    /** Number of entries in the store directory: 0 when absent or empty, null when it cannot be listed. */
    fun storeEntries(noBackupDir: File): Int? {
        val dir = File(noBackupDir, STORE_DIR)
        if (!dir.exists()) return 0
        return dir.list()?.size
    }

    fun secure(vaultHasKey: Boolean?, storeEntries: Int?, sessionReady: Boolean?): Boolean =
        vaultHasKey == false && storeEntries == 0 && sessionReady != true
}
