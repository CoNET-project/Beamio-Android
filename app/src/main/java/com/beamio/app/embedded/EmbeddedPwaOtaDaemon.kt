package com.beamio.app.embedded

/**
 * Remote PWA update daemon, as seen by the always-compiled code. The implementation
 * (EmbeddedPwaUpdateDaemon: remote manifest, download, staging) lives in `src/ota/java` and is compiled
 * only into non-store build types; the `store` build type compiles `src/noota/java`, whose
 * [EmbeddedPwaOtaFactory] returns null, so a store APK contains no remote-install code.
 */
interface EmbeddedPwaOtaDaemon {
    fun start()
    fun stop()
    fun checkNow()
}
