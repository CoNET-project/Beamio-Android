package com.beamio.app
import network.conet.chat.BeamioOpenPgpHost
import network.conet.chat.BeamioSiCipherPost
import network.conet.chat.BeamioChatPgpStore

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONObject
import network.conet.chat.nativekey.VoiceOfferDecrypt
import kotlin.math.max
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Killed-app path: encrypt `voice_offer_fetch` to mailbox route PGP →
 * `POST http://{entryIp}/post` (shell picks an IP ≠ mailbox B) → decrypt
 * `offerArmor` with stored user PGP → EIP-191 recover caller →
 * exact-address BeamioTag → update Incoming UI.
 *
 * Concurrent callers (FCM resolve + Decline `resolveBlocking`) **join** the same
 * in-flight fetch — iOS allows concurrent resolve; Android must not drop the
 * second waiter (that left Decline with a null offer while dialer kept ringing).
 */
object BeamioVoiceOfferIdentity {
    private const val TAG = "BeamioVoiceOfferId"
    /** Answer / Decline waiting on an offer re-fetch this often while nothing is in flight. */
    private const val RESOLVE_RETRY_MS = 1_000L
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val resolveRunning = AtomicBoolean(false)
    private val waiters = CopyOnWriteArrayList<(ResolvedIdentity) -> Unit>()

    data class ResolvedIdentity(
        val callerEoa: String,
        val beamioTag: String?,
        val shortAddress: String,
        val callId: String,
        /** Ring ID of the call (offer index, push handle; not a channel). */
        val sessionId: String,
        /** Offer `to` (local callee EOA when present). */
        val to: String = "",
        /** Voice protocol v3 (the callee creates the paid channels on Answer). */
        val proto: Int = 0,
        /** Caller's user-PGP public key and mailbox route key (armored), signed in the offer. */
        val callerPgpArmored: String = "",
        val callerRouteArmored: String = "",
        /** True only when the shell verified the offer (envelope and signatures). The PWA-reported display path stays false. */
        val verified: Boolean = false,
    ) {
        /** Enough to answer or decline: a v3 offer with the caller's keys. */
        val answerable: Boolean
            get() = proto == 3 &&
                callerPgpArmored.contains("BEGIN PGP PUBLIC KEY") &&
                callerRouteArmored.contains("BEGIN PGP PUBLIC KEY")
    }

    /** base64 armored public key → armor, or "" when absent / not a public key. */
    fun decodeArmor(raw: String): String {
        if (raw.isBlank()) return ""
        return runCatching {
            String(android.util.Base64.decode(raw.trim(), android.util.Base64.DEFAULT), Charsets.UTF_8)
        }.getOrNull()?.takeIf { it.contains("BEGIN PGP PUBLIC KEY") }.orEmpty()
    }

    fun scheduleResolve(
        context: Context,
        callId: String,
        sessionId: String = "",
        onResolved: (ResolvedIdentity) -> Unit,
    ) {
        val app = context.applicationContext
        val cid = callId.trim()
        if (cid.isEmpty()) return
        // Cache hit — no network.
        BeamioNativeVoiceSignaling.cachedOffer(cid, sessionId)
            ?.takeIf { it.answerable }
            ?.let { hit ->
                main.post { onResolved(hit) }
                return
            }

        waiters.add(onResolved)
        if (!resolveRunning.compareAndSet(false, true)) {
            Log.i(TAG, "resolve already in-flight; join waiters callId=${cid.take(12)}")
            return
        }
        io.execute {
            var identity: ResolvedIdentity? = null
            try {
                val secrets = BeamioChatPgpStore.load(app)
                if (secrets == null) { // TEMP local integration (A1): no WebView private key check
                    Log.w(TAG, "no stored user PGP; skip resolve")
                    return@execute
                }
                if (!secrets.hasRoutePublic) {
                    Log.w(TAG, "no mailbox route public; skip resolve")
                    return@execute
                }
                val roster = rosterOf(secrets)
                if (roster.isEmpty()) {
                    Log.w(TAG, "no SI IP roster; skip resolve")
                    return@execute
                }
                val command = JSONObject()
                    .put("command", "voice_offer_fetch")
                    .put("callId", cid)
                    .put("sessionId", sessionId.trim())
                    .put("timestamp", System.currentTimeMillis() / 1000L)
                val encryptWait = Object()
                var armor: String? = null
                var encryptError: String? = null
                BeamioNativeRoutePgp.encryptToRouteAsync(app, 
                    secrets.routePublicKeyArmor,
                    command.toString(),
                ) { result ->
                    result.onSuccess { armor = it }
                        .onFailure { encryptError = it.message }
                    synchronized(encryptWait) { encryptWait.notifyAll() }
                }
                synchronized(encryptWait) {
                    if (armor == null && encryptError == null) {
                        encryptWait.wait(15_000L)
                    }
                }
                val encrypted = armor
                if (encrypted.isNullOrBlank()) {
                    Log.w(TAG, "encrypt failed: ${encryptError ?: "timeout"}")
                    return@execute
                }
                val exclude = buildSet {
                    BeamioSiCipherPost.normalizeIp(secrets.mailboxIp)?.let { add(it) }
                }
                val posted = BeamioSiCipherPost.post(encrypted, roster, exclude)
                val offerArmor = extractOfferArmor(posted.body)
                if (offerArmor.isNullOrBlank()) {
                    Log.w(TAG, "voice_offer_fetch empty status=${posted.status} err=${posted.error}")
                    return@execute
                }
                val decryptWait = Object()
                var payload: JSONObject? = null
                var decryptError: String? = null
                // chat-sdk-android 0.2.1 `decryptAndVerifyOffer` always reports
                // decrypt_fail: its async JS returns a Promise to evaluateJavascript,
                // which hands back "{}". Same checks via bridge methods that work.
                decryptAndVerifyOfferViaBridge(app, offerArmor) { result -> // TEMP local integration (A1)
                    result.onSuccess { payload = it }
                        .onFailure { decryptError = it.message }
                    synchronized(decryptWait) { decryptWait.notifyAll() }
                }
                synchronized(decryptWait) {
                    if (payload == null && decryptError == null) {
                        decryptWait.wait(20_000L)
                    }
                }
                val verified = payload
                if (verified == null) {
                    Log.w(TAG, "decrypt/verify failed: ${decryptError ?: "timeout"}")
                    logOfferKeyMismatch(offerArmor, secrets)
                    return@execute
                }
                val caller = verified.optString("callerEoa", "").trim().lowercase()
                if (!caller.matches(Regex("^0x[0-9a-f]{40}$"))) {
                    Log.w(TAG, "invalid recovered caller")
                    return@execute
                }
                val to = verified.optString("to", "").trim().lowercase()
                // The page's local mirror first: no lookup leaves the phone for a known caller.
                val tag = BeamioCallerAvatarStore.tagFor(app, caller) ?: fetchExactTag(caller)
                val short = shortAddress(caller)
                val resolved = ResolvedIdentity(
                    callerEoa = caller,
                    beamioTag = tag,
                    shortAddress = short,
                    callId = verified.optString("callId", cid).ifBlank { cid },
                    sessionId = verified.optString("sessionId", sessionId).ifBlank { sessionId },
                    to = to,
                    proto = verified.optInt("proto", 0),
                    callerPgpArmored = verified.optString("callerPgpArmored", ""),
                    callerRouteArmored = verified.optString("callerRouteArmored", ""),
                    verified = true,
                )
                identity = resolved
                if (resolved.answerable) {
                    BeamioNativeVoiceSignaling.rememberOffer(resolved)
                    // The push already rang this device: wake receipt to the caller.
                    BeamioNativeVoiceSignaling.sendRingingIfNeeded(app, resolved)
                }
                Log.i(
                    TAG,
                    "resolved callId=${resolved.callId.take(12)} tag=${tag ?: "-"} eoa=$short " +
                        "v3=${if (resolved.answerable) "yes" else "no"}",
                )
            } catch (error: Exception) {
                Log.w(TAG, "resolve failed: ${error.message}")
            } finally {
                val done = identity?.takeIf { it.answerable }
                    ?: BeamioNativeVoiceSignaling.cachedOffer(cid, sessionId)
                        ?.takeIf { it.answerable }
                val callbacks = waiters.toList()
                waiters.clear()
                resolveRunning.set(false)
                if (done != null) {
                    main.post {
                        callbacks.forEach { cb ->
                            try {
                                cb(done)
                            } catch (e: Exception) {
                                Log.w(TAG, "waiter failed: ${e.message}")
                            }
                        }
                        // Waiters that joined after clear / before unlock.
                        val extra = waiters.toList()
                        waiters.clear()
                        extra.forEach { cb ->
                            try {
                                cb(done)
                            } catch (_: Exception) {
                            }
                        }
                    }
                } else {
                    Log.w(TAG, "resolve finished without a v3 offer; ${callbacks.size} waiter(s) not notified")
                }
            }
        }
    }

    /**
     * Decrypt a `voice_call_offer_v1` armor and verify the caller signature —
     * the same checks as the SDK's `decryptAndVerifyOffer`, built on
     * `decryptInboundArmor` + `verifyMessage`, which return results correctly.
     * Success JSON: callerEoa, callId, sessionId, to, claimedTag, proto, caller keys.
     */
    /** Callee dedupe table, persisted under the app files dir (R3AE-1, r3af). */
    @Volatile private var dedupeStore: VoiceOfferDedupeStore? = null

    private fun dedupe(app: Context): VoiceOfferDedupeStore =
        dedupeStore ?: synchronized(this) {
            dedupeStore ?: VoiceOfferDedupeStore(
                java.io.File(app.filesDir, "voice_offer_dedupe.json"),
            ) { System.currentTimeMillis() }.also { dedupeStore = it }
        }

    /**
     * Decrypt the armored offer (SDK VoiceOfferDecrypt, native vault), then verify the inner
     * offer signature (R must equal the claimed from), then admit (R3AE-2 order: window, duplicate,
     * quota) and record before the ring. Any failure is a failure callback: no ring (fail closed).
     * The SDK does not verify the signature; that is done here.
     */
    private fun decryptAndVerifyOfferViaBridge(
        app: Context,
        offerArmor: String,
        callback: (Result<JSONObject>) -> Unit,
    ) {
        val res = runCatching { VoiceOfferDecrypt.decryptVoiceOffer(app, offerArmor) }.getOrElse {
            callback(Result.failure(IllegalStateException("decrypt_threw")))
            return
        }
        when (res) {
            is VoiceOfferDecrypt.Result.Fail -> callback(Result.failure(IllegalStateException(res.code)))
            is VoiceOfferDecrypt.Result.Ok -> {
                // Outer envelope (qa.5 gives from and signMessage only, not the signed text):
                // the envelope signature cannot be checked without that text, so refuse
                // envelope-form offers (fail closed; 29 v30 §33, chat interface spec 29 §50(3)).
                // Envelope required (29 v30 §33; v49 §55): a bare signal is refused; the outer envelope
                // signature must recover envelopeFrom over envelopeText, and envelopeFrom must equal the
                // inner from. Nothing is verified, admitted, recorded or rung otherwise.
                val envelopeForm = res.envelopeFrom.isNotEmpty() || res.envelopeSignMessage.isNotEmpty() ||
                    res.envelopeText.isNotEmpty()
                if (!envelopeForm) {
                    callback(Result.failure(IllegalStateException("bare_signal_refused")))
                    return
                }
                if (res.envelopeText.isEmpty() || res.envelopeSignMessage.isEmpty() || res.envelopeFrom.isEmpty()) {
                    callback(Result.failure(IllegalStateException("envelope_incomplete")))
                    return
                }
                val signal = runCatching { JSONObject(res.signalJson) }.getOrNull()
                if (signal == null) {
                    callback(Result.failure(IllegalStateException("signal_json_invalid")))
                    return
                }
                val v = VoiceOfferWire.verifiedFields(signal)
                if (v == null) {
                    callback(Result.failure(IllegalStateException("offer_signature_not_verified")))
                    return
                }
                if (!VoiceOfferWire.outerEnvelopeOk(res.envelopeText, res.envelopeSignMessage, res.envelopeFrom, v.from)) {
                    callback(Result.failure(IllegalStateException("envelope_not_verified")))
                    return
                }
                if (res.callId != v.callId || res.sessionId != v.sessionId) {
                    callback(Result.failure(IllegalStateException("identifier_mismatch")))
                    return
                }
                val verdict = dedupe(app).admitOffer(
                    v.recoveredR, v.from, v.callId, v.sessionId, v.createdAtMs, v.expiresAtMs,
                )
                if (verdict is VoiceOfferAdmission.Verdict.Refuse) {
                    callback(Result.failure(IllegalStateException("admission_" + verdict.reason.name.lowercase())))
                    return
                }
                val out = JSONObject()
                    .put("callerEoa", v.from)
                    .put("callId", v.callId)
                    .put("sessionId", v.sessionId)
                    .put("to", v.to)
                    .put("proto", v.proto)
                    .put("callerPgpArmored", v.callerPgp)
                    .put("callerRouteArmored", v.callerRoute)
                callback(Result.success(out))
            }
        }
    }

    /**
     * Find the `voice_call_offer_v1` object in decrypted plaintext. Same walk
     * as iOS: JSON or base64(JSON) at the root, then nested objects, nested
     * `text` strings and JSON-in-string values, up to 8 levels deep.
     */
    private fun extractVoiceOffer(plaintext: String): JSONObject? {
        fun parse(s: String): JSONObject? {
            val t = s.trim()
            if (!t.startsWith("{")) return null
            return runCatching { JSONObject(t) }.getOrNull()
        }
        fun walk(value: Any?, depth: Int): JSONObject? {
            if (depth >= 8 || value == null) return null
            when (value) {
                is JSONObject -> {
                    if (value.optString("type") == "voice_call_offer_v1") return value
                    val keys = value.keys()
                    while (keys.hasNext()) {
                        walk(value.opt(keys.next()), depth + 1)?.let { return it }
                    }
                }
                is org.json.JSONArray -> {
                    for (i in 0 until value.length()) walk(value.opt(i), depth + 1)?.let { return it }
                }
                is String -> parse(value)?.let { return walk(it, depth + 1) }
            }
            return null
        }
        parse(plaintext)?.let { return walk(it, 0) }
        val decoded = runCatching {
            String(
                android.util.Base64.decode(plaintext.replace(Regex("\\s+"), ""), android.util.Base64.DEFAULT),
                Charsets.UTF_8,
            )
        }.getOrNull() ?: return null
        return parse(decoded)?.let { walk(it, 0) }
    }

    /**
     * Diagnostics for an offer this device cannot decrypt: which key the
     * dialer encrypted to, versus the key stored here and the one published
     * on chain for this wallet. Key IDs only, never key material.
     */
    private fun logOfferKeyMismatch(offerArmor: String, secrets: BeamioChatPgpStore.Secrets) {
        runCatching {
            val recipients = BeamioPgpKeyIds.messageRecipients(offerArmor)
            val local = BeamioPgpKeyIds.publicKeyIds(secrets.publicKeyArmor)
            val published = BeamioAddressPgp.searchKey(secrets.eoa)
                ?.let { BeamioPgpKeyIds.publicKeyIds(it.userPublicKeyArmored) }
                .orEmpty()
            val match = recipients.any { it in local }
            Log.w(
                TAG,
                "offer key check recipients=$recipients local=$local published=$published " +
                    "recipientIsLocal=$match localMatchesPublished=${local.toSet() == published.toSet()}",
            )
        }.onFailure { Log.w(TAG, "offer key check failed: ${it.message}") }
    }

    private fun rosterOf(secrets: BeamioChatPgpStore.Secrets): List<BeamioChatPgpStore.SiNode> {
        if (secrets.siNodes.isNotEmpty()) return secrets.siNodes
        return secrets.entryDomains.mapNotNull { raw ->
            val ip = BeamioSiCipherPost.normalizeIp(raw) ?: return@mapNotNull null
            BeamioChatPgpStore.SiNode(ip)
        }
    }

    private fun extractOfferArmor(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.contains("BEGIN PGP MESSAGE")) {
            try {
                val obj = JSONObject(trimmed)
                val armor = obj.optString("offerArmor", "")
                    .ifBlank { obj.optString("data", "") }
                if (armor.contains("BEGIN PGP MESSAGE")) return armor
            } catch (_: Exception) {
                return trimmed
            }
        }
        return try {
            val obj = JSONObject(trimmed)
            if (!obj.optBoolean("ok", true) && obj.has("error")) return null
            val armor = obj.optString("offerArmor", "")
                .ifBlank { obj.optString("data", "") }
            armor.takeIf { it.contains("BEGIN PGP MESSAGE") }
        } catch (_: Exception) {
            null
        }
    }

    fun fetchExactTag(address: String): String? {
        val trimmed = address.trim()
        if (!trimmed.matches(Regex("^0x[0-9a-fA-F]{40}$"))) return null
        // The search-users request goes to beamio.ca only, with a single checked redirect (SearchUsersLookup).
        return try {
            val text = com.beamio.app.search.SearchUsersLookup.fetchBody(trimmed) ?: return null
            val json = JSONObject(text)
            val results = json.optJSONArray("results") ?: return null
            val lower = trimmed.lowercase()
            for (i in 0 until results.length()) {
                val row = results.optJSONObject(i) ?: continue
                val addr = row.optString("address", "").lowercase()
                if (addr != lower) continue
                val username = row.optString("username", "")
                    .ifBlank { row.optString("accountName", "") }
                return normalizeTag(username)
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    fun shortAddress(eoa: String): String {
        val a = eoa.trim()
        if (a.length < 10) return a
        return "${a.take(6)}…${a.takeLast(4)}"
    }

    fun normalizeTag(raw: String?): String? {
        val t = raw?.trim().orEmpty()
        if (t.isEmpty()) return null
        return if (t.startsWith("@")) t else "@$t"
    }

    /** Delay helper for PushKit/FCM: resolve after notification shown. */
    fun scheduleResolveDelayed(
        context: Context,
        callId: String,
        sessionId: String = "",
        delayMs: Long = 400L,
        onResolved: (ResolvedIdentity) -> Unit,
    ) {
        val delay = max(0L, delayMs)
        main.postDelayed(
            { scheduleResolve(context, callId, sessionId, onResolved) },
            delay,
        )
    }

    /**
     * Blocking resolve for native Decline when cache miss races ahead of UI resolve.
     * Must be called off the main thread. Joins in-flight [scheduleResolve] waiters
     * (iOS parity: concurrent resolve allowed). Wall-clock covers encrypt(15s)+decrypt(20s).
     */
    fun resolveBlocking(
        context: Context,
        callId: String,
        sessionId: String,
        timeoutMs: Long = 45_000L,
    ): ResolvedIdentity? {
        BeamioNativeVoiceSignaling.cachedOffer(callId, sessionId)
            ?.takeIf { it.answerable }
            ?.let { return it }

        val wait = Object()
        var out: ResolvedIdentity? = null
        var done = false
        val onResolved: (ResolvedIdentity) -> Unit = { identity ->
            synchronized(wait) {
                out = identity
                done = true
                wait.notifyAll()
            }
        }
        scheduleResolve(context, callId, sessionId, onResolved)
        val deadline = System.currentTimeMillis() + timeoutMs
        var nextFetchAt = System.currentTimeMillis() + RESOLVE_RETRY_MS
        while (System.currentTimeMillis() < deadline) {
            BeamioNativeVoiceSignaling.cachedOffer(callId, sessionId)
                ?.takeIf { it.answerable }
                ?.let { return it }
            synchronized(wait) {
                if (done) return@synchronized
                val remain = deadline - System.currentTimeMillis()
                if (remain <= 0L) return@synchronized
                wait.wait(minOf(200L, remain))
            }
            if (done) break
            // A fetch that came back empty (offer not stored yet, entry or
            // mailbox briefly down) leaves no fetch running: try again instead
            // of waiting for the page to deliver the offer.
            val now = System.currentTimeMillis()
            if (now >= nextFetchAt && !resolveRunning.get()) {
                nextFetchAt = now + RESOLVE_RETRY_MS
                Log.i(TAG, "resolve retry callId=${callId.take(12)}")
                scheduleResolve(context, callId, sessionId, onResolved)
            }
        }
        return out?.takeIf { it.answerable }
            ?: BeamioNativeVoiceSignaling.cachedOffer(callId, sessionId)
                ?.takeIf { it.answerable }
    }
}
