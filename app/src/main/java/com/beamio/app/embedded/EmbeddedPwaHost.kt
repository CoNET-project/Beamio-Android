package com.beamio.app.embedded

import android.content.Context
import android.net.Uri
import android.webkit.WebView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.beamio.app.BuildConfig

/**
 * Local SilentPassUI host: bootstrap bundle, serve via WebViewAssetLoader, OTA daemon.
 * Store builds (BuildConfig.REMOTE_PWA_UPDATE == false) serve only the bundled zip: no daemon, no staging,
 * and the bundled zip must match BuildConfig.PWA_ZIP_SHA256 (see EmbeddedPwaBundleStore).
 */
class EmbeddedPwaHost(context: Context) {
    private val appContext = context.applicationContext
    val remotePwaUpdate: Boolean = BuildConfig.REMOTE_PWA_UPDATE
    val bundleStore = EmbeddedPwaBundleStore(appContext, remotePwaUpdate, BuildConfig.PWA_ZIP_SHA256)

    /**
     * Capability bit for the page (store-build OTA shell/PWA protocol, PM decision 2026-11-12):
     * only builds with remote PWA update declare it, at document start. The script text comes from
     * the `ota` source set; the store build type has none (and does not inject `applyEmbeddedPwaUpdate`).
     */
    fun installCapabilityScript(webView: WebView) {
        if (!BuildConfig.REMOTE_PWA_UPDATE) return
        val js = EmbeddedPwaOtaFactory.capabilityScript() ?: return
        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            WebViewCompat.addDocumentStartJavaScript(webView, js, setOf("*"))
        }
    }

    var assetLoader: WebViewAssetLoader? = null
        private set

    private var updateDaemon: EmbeddedPwaOtaDaemon? = null

    fun bootstrapIfNeeded() {
        bundleStore.bootstrapIfNeeded()
        buildAssetLoaderIfNeeded()
    }

    fun buildAssetLoaderIfNeeded() {
        if (assetLoader != null) return
        assetLoader = WebViewAssetLoader.Builder()
            .setDomain(EmbeddedPwaConstants.ASSET_LOADER_DOMAIN)
            .addPathHandler(
                "/",
                WebViewAssetLoader.InternalStoragePathHandler(appContext, bundleStore.activeDir),
            )
            .build()
    }

    /** Call after promoting staging → active so the loader rebinds to the new bundle files. */
    fun rebuildAssetLoader() {
        assetLoader = null
        buildAssetLoaderIfNeeded()
    }

    fun startUpdateDaemon(onUpdateAvailable: (currentVer: String, pendingVer: String) -> Unit) {
        if (!BuildConfig.REMOTE_PWA_UPDATE) {
            android.util.Log.i("BeamioEmbeddedPwa", "OTA disabled (store build): update daemon not created")
            return
        }
        if (updateDaemon != null) return
        updateDaemon = EmbeddedPwaOtaFactory.create(bundleStore, onUpdateAvailable, remotePwaUpdate)?.also { it.start() }
    }

    fun checkForUpdatesNow() {
        if (!remotePwaUpdate) return
        updateDaemon?.checkNow()
    }

    fun stopUpdateDaemon() {
        updateDaemon?.stop()
        updateDaemon = null
    }

    fun injectVersionGlobals(webView: WebView) {
        val current = escapeJs(bundleStore.activeVersion())
        val pending = escapeJs(bundleStore.pendingUpdateVersion() ?: "")
        val js =
            "(function(){try{" +
                "window.__CT_EMBEDDED_PWA_VER__='$current';" +
                "window.__CT_EMBEDDED_PWA_PENDING_VER__='$pending';" +
                "}catch(e){}})();"
        webView.evaluateJavascript(js, null)
    }

    /**
     * Map `https://beamio.ca/app/...` static assets to local loader URLs (PUBLIC_URL=/).
     * API / OG / metadata must bypass via [shouldBypassEmbeddedAssetLoader].
     */
    fun mapBeamioAppUrlToLocal(uri: Uri): Uri? {
        val host = uri.host?.lowercase() ?: return null
        if (!com.beamio.app.BeamioWebHosts.isWebHost(host)) return null
        if (shouldBypassEmbeddedAssetLoader(uri)) return null
        var path = uri.path ?: "/"
        when {
            // Marketing landing must never be served from the embedded bundle.
            path == "/app-download" || path.startsWith("/app-download/") -> path = "/index.html"
            path == "/app" || path == "/app/" -> path = "/index.html"
            path.startsWith("/app/") -> path = path.removePrefix("/app")
        }
        if (path.isEmpty() || path == "/") path = "/index.html"
        return Uri.parse(EmbeddedPwaConstants.ASSET_LOADER_ORIGIN + path).buildUpon()
            .encodedQuery(uri.encodedQuery)
            .fragment(uri.fragment)
            .build()
    }

    /**
     * The embedded bundle may have been built with PUBLIC_URL=/app.  Once
     * index.html is served from appassets.androidplatform.net, absolute
     * subresource URLs such as /app/beamio-launch.png no longer pass through
     * mapBeamioAppUrlToLocal and would otherwise be looked up verbatim.
     */
    fun mapEmbeddedAssetUrlToLocal(uri: Uri): Uri {
        val path = uri.path ?: "/"
        val normalizedPath = when {
            path == "/app-download" || path.startsWith("/app-download/") -> "/index.html"
            path == "/app" || path == "/app/" -> "/index.html"
            path.startsWith("/app/") -> path.removePrefix("/app")
            path.isEmpty() || path == "/" -> "/index.html"
            else -> path
        }
        return Uri.parse(EmbeddedPwaConstants.ASSET_LOADER_ORIGIN + normalizedPath)
            .buildUpon()
            .encodedQuery(uri.encodedQuery)
            .fragment(uri.fragment)
            .build()
    }

    /**
     * Network-only beamio.ca paths (API, OG, metadata). Must not be served from
     * `silentpass_pwa/active/` — otherwise onboarding hangs waiting on fetch.
     */
    fun shouldBypassEmbeddedAssetLoader(uri: Uri): Boolean {
        val path = uri.path?.trim().orEmpty().ifEmpty { "/" }
        if (path == "/api" || path.startsWith("/api/")) return true
        if (path == "/og" || path.startsWith("/og/")) return true
        if (path == "/metadata" || path.startsWith("/metadata/")) return true
        return false
    }

    private fun escapeJs(raw: String): String =
        raw.replace("\\", "\\\\").replace("'", "\\'")
}
