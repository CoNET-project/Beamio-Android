package com.beamio.app

import android.app.Application
import com.beamio.app.net.LegacyBeamioHostGuard

/**
 * Installs the legacy-host guard (2026-11-17) before any component of the process runs, including push wake-ups
 * (FirebaseMessagingService, call receivers, send-hold jobs) that can reach the chat SDK without MainActivity.
 */
class BeamioGuardApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        LegacyBeamioHostGuard.install()
    }
}
