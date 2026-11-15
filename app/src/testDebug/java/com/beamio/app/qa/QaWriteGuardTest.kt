package com.beamio.app.qa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class QaWriteGuardTest {
    private val api = "https://beamio.ca/api/addUser"

    @Test
    fun readsAndLocalRequestsPassNatively() {
        assertTrue(QaWriteGuard.nativeAllows("GET", "https", "beamio.ca", api))
        assertTrue(QaWriteGuard.nativeAllows("HEAD", "https", "beamio.ca", api))
        assertTrue(QaWriteGuard.nativeAllows("OPTIONS", "https", "beamio.ca", api))
        assertTrue(QaWriteGuard.nativeAllows("POST", "https", "appassets.androidplatform.net", "https://appassets.androidplatform.net/x"))
        assertTrue(QaWriteGuard.nativeAllows("POST", "blob", null, "blob:https://x/1"))
        assertTrue(QaWriteGuard.nativeAllows("POST", "data", null, "data:,x"))
    }

    /** Worker or other requests the page script never registered are refused. */
    @Test
    fun unregisteredWritesAreRefused() {
        assertFalse(QaWriteGuard.nativeAllows("POST", "https", "beamio.ca", api, now = 1_000))
        assertFalse(QaWriteGuard.nativeAllows("PUT", "http", "1.2.3.4", "http://1.2.3.4/post", now = 1_000))
        assertFalse(QaWriteGuard.nativeAllows("DELETE", "https", "beamio.ca", api, now = 1_000))
    }

    @Test
    fun aRegistrationLetsExactlyOneMatchingRequestThroughWithinItsLifetime() {
        val rpc = "https://qa-probe.invalid/"
        QaWriteGuard.registerAllowance("post", "$rpc#frag", now = 10_000)
        assertFalse("other url", QaWriteGuard.nativeAllows("POST", "https", "qa-probe.invalid", "https://qa-probe.invalid/other", now = 10_001))
        assertTrue(QaWriteGuard.nativeAllows("POST", "https", "qa-probe.invalid", rpc, now = 10_001))
        assertFalse("used up", QaWriteGuard.nativeAllows("POST", "https", "qa-probe.invalid", rpc, now = 10_002))

        QaWriteGuard.registerAllowance("POST", rpc, now = 20_000)
        assertFalse("expired", QaWriteGuard.nativeAllows("POST", "https", "qa-probe.invalid", rpc, now = 20_000 + 15_001))
    }

    @Test
    fun logLinesCarryOnlyPublicFieldsAndAreRedacted() {
        val l = QaWriteGuard.line("""{"kind":"blocked","method":"POST","host":"beamio.ca","path":"/api/addUser","rpc":[],"extra":"","body":"secret"}""")
        assertEquals("guard blocked POST beamio.ca/api/addUser", l)
        val r = QaWriteGuard.redact("addr 0x" + "a".repeat(40) + " key 0x" + "b".repeat(64) + " mnemonic=abandon password: hunter2")
        assertTrue(r.contains("0xaaaa…aaaa"))
        assertFalse(r.contains("b".repeat(64)))
        assertTrue(r.contains("mnemonic=<redacted>"))
        assertTrue(r.contains("password=<redacted>"))
        assertFalse(r.contains("abandon") || r.contains("hunter2"))
    }

    @Test
    fun pageScriptHasTheAgreedRules() {
        val js = QaWriteGuard.pageScript()
        for (m in QaWriteGuard.READ_RPC_METHODS) assertTrue(m, js.contains("\"$m\""))
        assertFalse(js.contains("eth_sendRawTransaction"))
        assertFalse(js.contains("eth_sendTransaction"))
        for (h in QaWriteGuard.READ_HOSTS) assertTrue(h, js.contains("\"$h\""))
        assertFalse("no Kotlin template left", js.contains("\$rpcHosts") || js.contains("\$readHosts"))
        assertTrue(js.contains("qa_write_blocked"))
        assertTrue(js.contains("qa_websocket_refused"))
        assertTrue(js.contains("sendBeacon"))
        assertTrue(js.contains("G.allow(d.m, d.w.href)"))
        assertFalse("no Kotlin template left", js.contains("\$JS_NAME") || js.contains("\$reads"))
    }

    /** Only debug builds can turn it on; release and store compile it off; hooks are in every WebView client. */
    @Test
    fun buildFlagAndHooks() {
        val gradle = File("build.gradle.kts").readText()
        assertEquals(3, Regex("buildConfigField\\(\"boolean\", \"QA_WRITE_GUARD\"").findAll(gradle).count())
        assertTrue(gradle.contains("buildConfigField(\"boolean\", \"QA_WRITE_GUARD\", qaWriteGuard.toString())"))
        assertEquals(2, Regex("buildConfigField\\(\"boolean\", \"QA_WRITE_GUARD\", \"false\"\\)").findAll(gradle).count())
        // PM R675: the real guard is debug-only; release and store compile a no-op stub that is never active.
        val guard = File("src/debug/java/com/beamio/app/qa/QaWriteGuard.kt").readText()
        assertTrue(guard.contains("BuildConfig.DEBUG && BuildConfig.QA_WRITE_GUARD"))
        val stub = File("src/qaGuardStub/java/com/beamio/app/qa/QaWriteGuard.kt").readText()
        assertTrue(stub.contains("const val isActive: Boolean = false"))
        for (s in listOf("QA_EVAL", "BeamioQAGuard", "qa-probe", "JavascriptInterface", "addDocumentStartJavaScript")) assertTrue(s, !stub.contains(s))
        assertTrue(gradle.contains("getByName(\"release\").let { it.java.directories.add(\"src/qaGuardStub/java\")"))
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        for (src in listOf("page", "remote", "browser")) assertTrue(src, main.contains("QaWriteGuard.intercept(request, \"$src\")"))
        // The service worker backstop moved into the debug guard's installNativeHooks (PM R675).
        assertTrue("sw", guard.contains("intercept(request, \"sw\")"))
        assertTrue(main.contains("QaWriteGuard.installNativeHooks(this)") && main.contains("QaWriteGuard.installWebViewHooks(this)"))
        val voice = File("src/main/java/com/beamio/app/BeamioNativeVoiceChannel.kt").readText()
        assertEquals(2, Regex("QaWriteGuard\\.nativeWriteAllowed\\(").findAll(voice).count())
    }

    @Test
    fun workerPreludeKeepsStrictModeAndIsIdempotentInText() {
        val plain = QaWriteGuard.withWorkerPrelude("var a=1;")
        assertTrue(plain.startsWith(QaWriteGuard.WORKER_PRELUDE))
        assertTrue(plain.endsWith("var a=1;"))
        val strict = QaWriteGuard.withWorkerPrelude("\"use strict\";var a=1;")
        assertTrue(strict.startsWith("\"use strict\";" + QaWriteGuard.WORKER_PRELUDE))
        val single = QaWriteGuard.withWorkerPrelude("  'use strict'\nx()")
        assertTrue(single.startsWith("  'use strict'" + QaWriteGuard.WORKER_PRELUDE))
        assertTrue(QaWriteGuard.WORKER_PRELUDE.contains("WorkerGlobalScope") && QaWriteGuard.WORKER_PRELUDE.contains("qa_websocket_refused"))
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertEquals(2, Regex("QaWriteGuard\\.decorateScript\\(").findAll(main).count())
    }

    /** R336 section 2.2: exactly these eleven read methods; section 1: host allowlist. */
    @Test
    fun r336MethodAndHostLists() {
        assertEquals(
            listOf("eth_call", "eth_getCode", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionReceipt",
                "eth_getTransactionByHash", "eth_getLogs", "eth_estimateGas", "eth_gasPrice", "net_version"),
            QaWriteGuard.READ_RPC_METHODS,
        )
        assertTrue(QaWriteGuard.RPC_HOSTS.containsAll(listOf("publicrpc.conet.network", "base-rpc.conet.network", "mainnet.conet.network")))
        assertFalse("beamio.ca is not an RPC host", "beamio.ca" in QaWriteGuard.RPC_HOSTS)
        // GET only to listed hosts
        assertTrue(QaWriteGuard.nativeAllows("GET", "https", "beamio.ca", "https://beamio.ca/api/cardMetadata"))
        // PM R1637: the shell no longer reads from the old domain.
        assertFalse(QaWriteGuard.nativeAllows("GET", "https", "beamio.app", "https://beamio.app/api/cardMetadata"))
        assertTrue(QaWriteGuard.nativeAllows("GET", "https", "ipfs.conet.network", "https://ipfs.conet.network/x"))
        assertFalse(QaWriteGuard.nativeAllows("GET", "https", "hooks.conet.network", "https://hooks.conet.network/x"))
        assertFalse(QaWriteGuard.nativeAllows("GET", "https", "settleonbase.xyz", "https://settleonbase.xyz/x"))
        // non-GET to beamio.ca is refused even if something registered it
        QaWriteGuard.registerAllowance("POST", "https://beamio.ca/api/agentReferrerRegister", now = 50_000)
        assertFalse(QaWriteGuard.nativeAllows("POST", "https", "beamio.ca", "https://beamio.ca/api/agentReferrerRegister", now = 50_001))
    }

    @Test
    fun sdkCommandsThatWriteAreNotForwardedInGuardBuilds() {
        val allowed = QaWriteGuard.SDK_COMMANDS_ALLOWED
        for (t in listOf("init", "provisionIdentity", "pgpIdentityCreate", "pgpRestore", "send", "regiestChatRoute")) assertFalse(t, t in allowed)
        for (t in listOf("hello", "walletStatus", "nativeRecoveryOpen")) assertTrue(t, t in allowed)
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("QaWriteGuard.sdkCommandAllowed(body.optString(\"type\"))"))
        assertTrue(main.indexOf("QaWriteGuard.sdkCommandAllowed") < main.indexOf("BeamioConetChatModule.handleCommand(applicationContext, body)"))
    }
}
