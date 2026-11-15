package com.beamio.app.qa

import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import com.beamio.app.BuildConfig
import org.json.JSONObject
import java.io.ByteArrayInputStream

/**
 * QA-only write guard for the registration regression (PM and PWA integration lead, 2026-11-14). Same page rules as
 * the iOS shell (CashTreesQAWriteGuard), plus a native backstop that WKWebView does not have.
 *
 * Active only in debug builds made with `-PqaWriteGuard=true` (`BuildConfig.QA_WRITE_GUARD`); release and store
 * builds compile the flag as false.
 *
 * 1. Page script (document start, all frames): GET/HEAD/OPTIONS, the embedded asset host, data: and blob: pass; a
 *    JSON-RPC POST passes only when every method is a read. Anything else is refused before it is sent (fetch
 *    rejects with TypeError `qa_write_blocked`, XHR fires `error`, sendBeacon returns false). WebSocket construction
 *    throws. Before a passed non-GET request goes out, the script registers it with the shell ([allow]).
 * 2. Native backstop (`shouldInterceptRequest`, page and service worker): a non-GET request to any outside host
 *    passes only if the page script registered it a moment before. Requests the page script never saw (dedicated
 *    and service workers, other WebViews) are refused with a 403 that never reaches the network. This also refuses
 *    read-only JSON-RPC POSTs from workers (their bodies are not visible natively): fail closed.
 * 3. Native HTTP writes from the shell (voice channel POSTs to SI nodes) are refused via [nativeWriteAllowed].
 *
 * Logging: method, host and path only (no query, body or headers), redacted, logcat tag `BeamioQAGuard`.
 */
object QaWriteGuard {
    const val TAG = "BeamioQAGuard"
    const val JS_NAME = "BeamioQAGuard"
    private const val ASSET_HOST = "appassets.androidplatform.net"
    private const val ALLOW_TTL_MS = 15_000L

    val isActive: Boolean = BuildConfig.DEBUG && BuildConfig.QA_WRITE_GUARD

    /** Isolation fixture R336 section 2.2: the only JSON-RPC methods that pass. */
    val READ_RPC_METHODS = listOf(
        "eth_call", "eth_getCode", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionReceipt",
        "eth_getTransactionByHash", "eth_getLogs", "eth_estimateGas", "eth_gasPrice", "net_version",
    )

    /** R336 section 1: hosts whose JSON-RPC reads may pass. `qa-probe.invalid` is the synthetic probe host (never resolves). */
    val RPC_HOSTS = setOf(
        "mainnet.conet.network", "publicrpc.conet.network", "rpc1.conet.network", "base-rpc.conet.network",
        "cancun-rpc.conet.network", "ethereum-rpc.publicnode.com", "eth.llamarpc.com", "qa-probe.invalid",
    )

    /** R336 section 1: the only outside hosts reached at all (GET, plus RPC reads on [RPC_HOSTS]). Others are refused. */
    val READ_HOSTS = RPC_HOSTS + setOf("beamio.ca", "www.beamio.ca", "ipfs.conet.network")

    private val allowances = HashMap<String, MutableList<Long>>()

    // ---- decisions (pure, unit-tested) ----

    fun isReadMethod(method: String?): Boolean = when ((method ?: "GET").uppercase()) {
        "GET", "HEAD", "OPTIONS" -> true
        else -> false
    }

    fun isLocalHost(host: String?): Boolean = host.isNullOrEmpty() || host.lowercase() == ASSET_HOST

    fun key(method: String, url: String): String = method.uppercase() + " " + url.substringBefore('#')

    /** Page script registered a passed non-GET request. */
    fun registerAllowance(method: String, url: String, now: Long = System.currentTimeMillis()) {
        synchronized(allowances) {
            prune(now)
            allowances.getOrPut(key(method, url)) { mutableListOf() }.add(now + ALLOW_TTL_MS)
        }
    }

    /** Consumes one registration for this request; false when none is left. */
    fun consumeAllowance(method: String, url: String, now: Long = System.currentTimeMillis()): Boolean =
        synchronized(allowances) {
            prune(now)
            val list = allowances[key(method, url)] ?: return@synchronized false
            list.removeAt(0)
            if (list.isEmpty()) allowances.remove(key(method, url))
            true
        }

    private fun prune(now: Long) {
        val it = allowances.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            e.value.removeAll { exp -> exp < now }
            if (e.value.isEmpty()) it.remove()
        }
    }

    /** Native decision for one WebView request: true = let it go on. */
    fun nativeAllows(method: String?, scheme: String?, host: String?, url: String, now: Long = System.currentTimeMillis()): Boolean {
        val s = scheme?.lowercase()
        if (s != "http" && s != "https") return true // data:, blob:, file: never leave the device
        if (isLocalHost(host)) return true
        if (host!!.lowercase() !in READ_HOSTS) return false // R336 2.1: only the listed read-only hosts
        if (isReadMethod(method)) return true
        if (host.lowercase() !in RPC_HOSTS) return false
        return consumeAllowance(method ?: "POST", url, now)
    }

    // ---- WebView hooks ----

    /** Call first in shouldInterceptRequest. Returns a refusal response, or null to continue as usual. */
    fun intercept(request: WebResourceRequest, source: String): WebResourceResponse? {
        if (!isActive) return null
        val u = request.url ?: return null
        val method = request.method ?: "GET"
        if (nativeAllows(method, u.scheme, u.host, u.toString())) return null
        log("guard blocked-native $source ${method.uppercase()} ${u.host}${u.path ?: ""}")
        val headers = mapOf("Access-Control-Allow-Origin" to "*", "Cache-Control" to "no-store")
        return WebResourceResponse("text/plain", "utf-8", 403, "qa_write_blocked", headers, ByteArrayInputStream(ByteArray(0)))
    }

    /** Shell native HTTP write (POST to an outside host). false = refused (logged); callers must not send. */
    fun nativeWriteAllowed(what: String, host: String?): Boolean {
        if (!isActive) return true
        log("guard blocked-native-http $what ${host ?: "?"}")
        return false
    }

    /**
     * Worker prelude: workers have no page script, so in guard builds every embedded `.js` response gets this prepended
     * (after a leading "use strict" directive, so strict mode is kept). It does nothing in a window; in a worker it makes
     * WebSocket construction throw before any connection.
     */
    const val WORKER_PRELUDE =
        ";(function(){try{if(typeof WorkerGlobalScope!=='undefined'&&self instanceof WorkerGlobalScope&&!self.__beamioQAWs){" +
            "self.__beamioQAWs=true;var f=function(){throw new Error('qa_websocket_refused')};" +
            "try{Object.defineProperty(self,'WebSocket',{value:f,writable:false,configurable:false})}catch(e){self.WebSocket=f}" +
            // Controlled probe hook (guard builds only): {__beamioQAProbe:'ws'} tries a WebSocket to an .invalid host.
            "self.addEventListener('message',function(e){if(e&&e.data&&e.data.__beamioQAProbe==='ws'){e.stopImmediatePropagation();" +
            "var r;try{new self.WebSocket('wss://qa-probe.invalid/');r='constructed'}catch(x){r='threw '+x.message}" +
            "self.postMessage({__beamioQAProbe:'ws',result:r,prelude:self.__beamioQAWs===true})}},true)" +
            "}}catch(e){}})();\n"

    private val STRICT = Regex("^(\\uFEFF)?\\s*(['\"])use strict\\2;?")

    /** Script text with the worker prelude inserted (pure, unit-tested). */
    fun withWorkerPrelude(js: String): String {
        val m = STRICT.find(js) ?: return WORKER_PRELUDE + js
        return js.substring(0, m.range.last + 1) + WORKER_PRELUDE + js.substring(m.range.last + 1)
    }

    /** Guard builds: embedded `.js` responses get the worker prelude. Anything else is returned unchanged. */
    fun decorateScript(path: String?, response: WebResourceResponse?): WebResourceResponse? {
        if (!isActive || response == null || path?.endsWith(".js") != true) return response
        val data = response.data ?: return response
        return try {
            val text = data.use { it.readBytes() }.toString(Charsets.UTF_8)
            val out = withWorkerPrelude(text).toByteArray(Charsets.UTF_8)
            WebResourceResponse(response.mimeType ?: "text/javascript", "utf-8", response.statusCode.takeIf { it in 100..599 } ?: 200,
                response.reasonPhrase?.takeIf { it.isNotBlank() } ?: "OK", response.responseHeaders, ByteArrayInputStream(out))
        } catch (_: Exception) {
            response
        }
    }

    /**
     * R336 2.3: the native SDK's own HTTP is outside the WebView guard. In guard builds the shell passes only these
     * chat-module commands to the SDK (no network writes: handshake, status, native pages that read, cleanup).
     * Everything else (init, provisionIdentity, pgpIdentityCreate, pgpRestore, send, call control, ...) is answered
     * `qa_write_blocked` and never reaches the SDK.
     */
    val SDK_COMMANDS_ALLOWED = setOf(
        "hello", "walletStatus", "identityPublic", "destroy", "pgpRestoreEvaluate",
        "nativeRecoveryOpen", "nativeImportOpen", "nativeAccountCreateOpen",
        "walletCredential", // spec r3np §25.52Y.38: read-only, local; the shell trust gate runs before this guard
        "walletEoaAddress", // spec §25.52Y.42 item 5 (c): address only, read-only, local; same shell trust gate
    )

    /** true = forward to the SDK. Always true outside guard builds. */
    fun sdkCommandAllowed(type: String?): Boolean = !isActive || type in SDK_COMMANDS_ALLOWED

    class JsIface {
        @JavascriptInterface
        fun allow(method: String?, url: String?) {
            if (method.isNullOrEmpty() || url.isNullOrEmpty()) return
            registerAllowance(method, url)
        }

        @JavascriptInterface
        fun log(json: String?) {
            QaWriteGuard.log(line(json ?: "{}"))
        }
    }

    fun line(json: String): String = try {
        val o = JSONObject(json)
        fun s(k: String, n: Int) = o.optString(k, "").take(n)
        val rpc = o.optJSONArray("rpc")?.let { a -> (0 until minOf(a.length(), 6)).joinToString(",") { a.optString(it) } }.orEmpty()
        if (s("kind", 12) == "stage") "stage ${s("extra", 300)}"
        else "guard ${s("kind", 12)} ${s("method", 10)} ${s("host", 80)}${s("path", 120)}${if (rpc.isEmpty()) "" else " rpc=$rpc"} ${s("extra", 40)}".trimEnd()
    } catch (_: Exception) {
        "guard bad-message"
    }

    fun log(text: String) {
        Log.i(TAG, redact(text.take(400)))
    }

    /**
     * PM R675: the shell calls these two in every build; release and store get a no-op stub (src/qaGuardStub), so no QA
     * interface, page script or probe receiver is compiled into them.
     */
    fun installWebViewHooks(webView: android.webkit.WebView) {
        if (!isActive) return
        webView.addJavascriptInterface(JsIface(), JS_NAME)
        if (androidx.webkit.WebViewFeature.isFeatureSupported(androidx.webkit.WebViewFeature.DOCUMENT_START_SCRIPT)) {
            androidx.webkit.WebViewCompat.addDocumentStartJavaScript(webView, pageScript(), setOf("*"))
            log("guard page-script registered")
        } else {
            // Without the page script nothing registers allowances: the native backstop refuses every write.
            log("guard page-script unavailable; native backstop only")
        }
    }

    /**
     * Service worker backstop and the controlled probe receiver (`<applicationId>.QA_EVAL`, extra `js`, which runs a probe
     * script in the page). Returns the receiver so the activity can unregister it, or null when the guard is off.
     */
    fun installNativeHooks(activity: android.app.Activity, webViewOf: () -> android.webkit.WebView?): android.content.BroadcastReceiver? {
        if (!isActive) return null
        if (androidx.webkit.WebViewFeature.isFeatureSupported(androidx.webkit.WebViewFeature.SERVICE_WORKER_BASIC_USAGE)) {
            androidx.webkit.ServiceWorkerControllerCompat.getInstance().setServiceWorkerClient(
                object : androidx.webkit.ServiceWorkerClientCompat() {
                    override fun shouldInterceptRequest(request: WebResourceRequest): WebResourceResponse? = intercept(request, "sw")
                },
            )
            log("guard service-worker backstop installed")
        } else {
            log("guard service-worker backstop unavailable")
        }
        val r = object : android.content.BroadcastReceiver() {
            override fun onReceive(c: android.content.Context, i: android.content.Intent) {
                val js = i.getStringExtra("js") ?: return
                val id = i.getStringExtra("id") ?: "probe"
                val wv = webViewOf() ?: return
                wv.post { wv.evaluateJavascript(js) { v -> log("probe $id result ${v?.take(380)}") } }
            }
        }
        val filter = android.content.IntentFilter(activity.packageName + ".QA_EVAL")
        if (android.os.Build.VERSION.SDK_INT >= 33) activity.registerReceiver(r, filter, android.content.Context.RECEIVER_EXPORTED)
        else @Suppress("UnspecifiedRegisterReceiverFlag") activity.registerReceiver(r, filter)
        log("guard active (debug QA build)")
        return r
    }

    private val REDACTIONS: List<Pair<Regex, (String) -> String>> = listOf(
        Regex("0x[0-9a-fA-F]{41,}") to { _ -> "<hex>" },
        Regex("\\b[0-9a-fA-F]{64,}\\b") to { _ -> "<hex>" },
        Regex("0x[0-9a-fA-F]{40}\\b") to { a -> a.take(6) + "…" + a.takeLast(4) },
        Regex("[A-Za-z0-9+/_=-]{40,}") to { _ -> "<token>" },
        Regex("(?i)(masterkey|mnemonic|privatekey|password|secret|seed)[=:\"' ]+(?!(?:true|false|null|undefined)\\b)[^ ,&\"']+") to
            { m -> (m.split('=', ':', '"', '\'', ' ').firstOrNull { it.isNotEmpty() } ?: "field") + "=<redacted>" },
    )

    fun redact(text: String): String = REDACTIONS.fold(text) { t, (re, f) -> re.replace(t) { f(it.value) } }

    fun pageScript(): String {
        val reads = READ_RPC_METHODS.joinToString(",") { "\"$it\"" }
        val rpcHosts = RPC_HOSTS.joinToString(",") { "\"$it\"" }
        val readHosts = READ_HOSTS.joinToString(",") { "\"$it\"" }
        return """
        (function(){
          if (window.__beamioQAGuard) return; window.__beamioQAGuard = true;
          var G = window.$JS_NAME;
          var READS = {}; [$reads].forEach(function(m){ READS[m] = true; });
          var RPCH = {}; [$rpcHosts].forEach(function(h){ RPCH[h] = true; });
          var READH = {}; [$readHosts].forEach(function(h){ READH[h] = true; });
          function post(o){ try { G.log(JSON.stringify(o)); } catch(e) {} }
          function where(u){ try { var x = new URL(String(u), location.href); return {p: x.protocol, h: x.host, path: x.pathname, href: x.href.split('#')[0]}; } catch(e) { return {p:'', h:'?', path:'?', href:''}; } }
          function rpcMethods(text){
            if (typeof text !== 'string') return null;
            try { var j = JSON.parse(text); var a = Array.isArray(j) ? j : [j]; var out = [];
              for (var i = 0; i < a.length; i++) { if (!a[i] || typeof a[i].method !== 'string') return null; out.push(a[i].method); }
              return out.length ? out : null; } catch(e) { return null; }
          }
          function decide(method, url, bodyText){
            var w = where(url), m = String(method || 'GET').toUpperCase();
            if (w.p === 'data:' || w.p === 'blob:' || w.h === '$ASSET_HOST') return {ok: true, w: w, m: m, local: true};
            var host = String(w.h || '').toLowerCase().replace(/:\d+$/, '');
            if (READH[host] !== true) return {ok: false, w: w, m: m, why: 'host'};
            if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return {ok: true, w: w, m: m, local: true};
            var rpc = rpcMethods(bodyText);
            if (RPCH[host] === true && rpc && rpc.every(function(x){ return READS[x] === true; })) return {ok: true, w: w, m: m, rpc: rpc};
            return {ok: false, w: w, m: m, rpc: rpc};
          }
          function bodyText(b){
            try {
              if (b == null) return null;
              if (typeof b === 'string') return b;
              if (b instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(b));
              if (ArrayBuffer.isView(b)) return new TextDecoder().decode(new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
            } catch(e) {}
            return undefined;
          }
          function log(kind, d, extra){ post({kind: kind, method: d.m, host: d.w.h, path: d.w.path, rpc: d.rpc || [], extra: extra || (d.why || '')}); }
          function pass(d){ if (!d.local) { try { G.allow(d.m, d.w.href); } catch(e) {} } }
          var ofetch = window.fetch;
          if (typeof ofetch === 'function') {
            window.fetch = function(input, init){
              var url = (input && typeof input === 'object' && 'url' in input) ? input.url : input;
              var method = (init && init.method) || (input && typeof input === 'object' && input.method) || 'GET';
              var bodyP;
              if (init && 'body' in init) {
                var bt = bodyText(init.body);
                bodyP = (bt === undefined && init.body && typeof init.body.text === 'function') ? init.body.text().catch(function(){ return null; }) : Promise.resolve(bt === undefined ? null : bt);
              }
              else if (input && typeof input === 'object' && typeof input.clone === 'function' && String(method).toUpperCase() !== 'GET') bodyP = input.clone().text().catch(function(){ return null; });
              else bodyP = Promise.resolve(null);
              var self = this, args = arguments;
              return bodyP.then(function(body){
                var d = decide(method, url, body);
                if (!d.ok) { log('blocked', d); return Promise.reject(new TypeError('qa_write_blocked')); }
                log('request', d); pass(d);
                return ofetch.apply(self, args).then(function(r){ log('response', d, String(r.status)); return r; },
                                                     function(e){ log('failed', d, String(e && e.name || 'error')); throw e; });
              });
            };
          }
          var XO = XMLHttpRequest.prototype.open, XS = XMLHttpRequest.prototype.send;
          XMLHttpRequest.prototype.open = function(method, url){ this.__qa = {method: method, url: url}; return XO.apply(this, arguments); };
          XMLHttpRequest.prototype.send = function(body){
            var q = this.__qa || {method: 'GET', url: ''};
            var d = decide(q.method, q.url, bodyText(body));
            if (!d.ok) { log('blocked', d); var x = this; setTimeout(function(){ try { x.dispatchEvent(new ProgressEvent('error')); } catch(e) {} }, 0); return; }
            log('request', d); pass(d);
            var x2 = this; this.addEventListener('loadend', function(){ log('response', d, String(x2.status)); });
            return XS.apply(this, arguments);
          };
          if (navigator.sendBeacon) {
            navigator.sendBeacon = function(url){ var d = decide('POST', url, null); log('blocked', d, 'beacon'); return false; };
          }
          var refuse = function(){ post({kind: 'blocked', method: 'WEBSOCKET', host: '', path: '', rpc: [], extra: 'constructor'}); throw new Error('qa_websocket_refused'); };
          try { Object.defineProperty(window, 'WebSocket', {value: refuse, writable: false, configurable: false}); } catch(e) { window.WebSocket = refuse; }
          var seen = 0;
          setInterval(function(){
            try {
              var a = window.__beamioAcctStages;
              if (!Array.isArray(a)) return;
              for (; seen < a.length; seen++) post({kind: 'stage', method: '', host: '', path: '', rpc: [], extra: JSON.stringify(a[seen]).slice(0, 300)});
            } catch(e) {}
          }, 1000);
          post({kind: 'installed', method: '', host: location.host, path: location.pathname, rpc: [], extra: ''});
        })();
        """.trimIndent()
    }
}
