package com.beamio.app.nativekey

import android.content.Context
import network.conet.chat.nativekey.NativeAccountCreate
import network.conet.chat.nativekey.NativeAccountCreateHost
import network.conet.chat.nativekey.NativeImport
import network.conet.chat.nativekey.NativeImportHost
import network.conet.chat.nativekey.NativeRecovery
import network.conet.chat.nativekey.NativeRecoveryHost
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletVault

/**
 * Chat SDK 0.2.7 line (`-PchatSdkNativeKey=true`): the SDK's native vault and import, and its import host.
 *
 * - `NativeImportHost.launcher` opens the shell's native import page ([NativeKeyImportRoute]); the SDK answers
 *   `nativeImportOpen` with an ack that carries no data.
 * - No expected account is passed: SDK e69b6c2 does not expose the session's account to the shell, so the import
 *   only derives (spec 25.25.2 item 4, "no context"). Recorded as a platform difference.
 */
object NativeKeySdkBinding {
    const val ENABLED = true

    @Volatile
    private var installed = false

    fun install(context: Context) {
        if (installed) return
        synchronized(this) {
            if (installed) return
            val app = context.applicationContext
            NativeKeyBackends.current = SdkBackend(app)
            NativeImportHost.launcher = { NativeKeyImportRoute.open() }
            // QA: recovery by recovery code (spec r3u 25.42, path A). Its own page; never the import page.
            NativeRecoveryBackends.current = SdkRecoveryBackend(app)
            NativeRecoveryHost.launcher = { NativeRecoveryRoute.open() }
            // QA: native account create (SDK 0.2.15, spec r3w 25.46). Its own page.
            NativeAccountCreateBackends.current = SdkCreateBackend(app)
            NativeAccountCreateHost.launcher = { NativeAccountCreateRoute.open() }
            // Plan N (SDK 0.2.16 r3bh): first-run import from P and the page bridge handler.
            com.beamio.app.legacy.FirstRunImporters.current = SdkFirstRun(app)
            com.beamio.app.legacy.PageBridgeHandlers.current = SdkPageBridge(app)
            installed = true
        }
    }

    private class SdkBackend(private val app: Context) : NativeKeyBackend {
        override fun hasKey(): Boolean? = NativeWallet.vault(app).state() !is NativeWalletVault.State.NoKey

        override fun sessionReady(): Boolean? = network.conet.chat.BeamioConetChatModule.isNativeSessionReady()

        override fun importPrivateKey(raw: String): ImportCode =
            ImportCode.fromWire(NativeImport.submit(raw, null, NativeWallet.vault(app)).code.wire)

        override fun importMnemonic(raw: String): ImportCode =
            ImportCode.fromWire(NativeImport.submitMnemonic(raw, null, NativeWallet.vault(app)).code.wire)
    }

    /** SDK 0.2.11 paths A and B. Secrets go to the SDK only; both copies are wiped. Waits for the SDK's callback. */
    private class SdkRecoveryBackend(private val app: Context) : NativeRecoveryBackend {
        override val supported = true

        private fun await(start: ((network.conet.chat.nativekey.RecoveryOutcome) -> Unit) -> Unit): RecoveryOutcome {
            val done = java.util.concurrent.CountDownLatch(1)
            var out = RecoveryOutcome(RecoveryCode.NETWORK_ERROR)
            start { o ->
                out = RecoveryOutcome(RecoveryCode.fromWire(o.code), o.eoa, o.cooldownSec)
                done.countDown()
            }
            if (!done.await(90, java.util.concurrent.TimeUnit.SECONDS)) return RecoveryOutcome(RecoveryCode.NETWORK_ERROR)
            return out
        }

        override fun recover(recoveryCode: CharArray): RecoveryOutcome {
            val bytes = ByteArray(recoveryCode.size)
            for (i in recoveryCode.indices) bytes[i] = recoveryCode[i].code.toByte() // [0-9A-Za-z] only (checked before)
            return try {
                await { cb -> NativeRecovery.restoreWithRecoveryCode(app, bytes, cb) }
            } finally {
                bytes.fill(0)
            }
        }

        override fun recoverWithPassword(accountName: String, password: CharArray): RecoveryOutcome {
            val pw = password.copyOf()
            return try {
                await { cb -> NativeRecovery.restoreWithAccountPassword(app, accountName, pw, cb) }
            } finally {
                pw.fill('\u0000')
            }
        }

        override fun cancel() = NativeRecoveryHost.pageClosed()
    }

    /** SDK 0.2.15: the SDK generates, stores and reads back the key and sends the result to the web page itself. */
    private class SdkCreateBackend(private val app: Context) : NativeAccountCreateBackend {
        override val supported = true

        override fun confirm(done: (CreateCode) -> Unit) =
            NativeAccountCreate.confirm(app) { r -> done(CreateCode.fromWire(r.code.wire)) }

        override fun pageClosed() = NativeAccountCreateHost.pageClosed()
    }

    /** `BeamioPgpMigrationImport.importFirstRun`: page copy from P, PGP migration after import_ok. */
    private class SdkFirstRun(private val app: Context) : com.beamio.app.legacy.FirstRunImporter {
        override fun setMigrationPending(pending: Boolean) = network.conet.chat.nativekey.BeamioShellRecordImport.setMigrationPending(pending)

        override fun importFirstRun(eoa: String, record: ByteArray?, unreadableReason: String?, pgp: com.beamio.app.legacy.PgpMigrationRunner.Source?): String {
            val wallet = when {
                record != null -> network.conet.chat.nativekey.LegacyWalletRecord.Found(record)
                unreadableReason != null -> network.conet.chat.nativekey.LegacyWalletRecord.Unreadable(unreadableReason)
                else -> network.conet.chat.nativekey.LegacyWalletRecord.Absent
            }
            val src = pgp?.let { network.conet.chat.nativekey.LegacyPgpSource(it.privateArmor, it.publicArmor, it.keyId) }
            val code = network.conet.chat.nativekey.BeamioPgpMigrationImport.importFirstRun(app, eoa, wallet, src).wire
            // Public state name only (none, pending, failed, verified); the PGP step runs only after import_ok.
            val st = runCatching { network.conet.chat.nativekey.BeamioPgpMigrationImport.state(app, eoa, "default") }.getOrDefault("?")
            android.util.Log.i("BeamioShellRecord", "first run sdk: import=$code pgpState=$st")
            return code
        }
    }

    /** `BeamioShellRecordImport.handle` with the origin the shell verified. */
    private class SdkPageBridge(private val app: Context) : com.beamio.app.legacy.PageBridgeHandler {
        override fun handle(embeddedPage: Boolean, body: String, requestBytes: Int): String {
            val origin = if (embeddedPage) network.conet.chat.nativekey.ShellOrigin.EMBEDDED_PAGE else network.conet.chat.nativekey.ShellOrigin.OTHER
            val json = try { org.json.JSONObject(body) } catch (e: Exception) { org.json.JSONObject() }
            return network.conet.chat.nativekey.BeamioShellRecordImport.handle(app, origin, json, requestBytes).toString()
        }
    }
}
