import groovy.json.JsonSlurper
import java.security.MessageDigest
import java.util.Properties
import java.util.zip.ZipFile

import java.util.Collections
import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.ZipInputStream

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.google.services)
}

// Release signing: same keystore as Android-init-NDEF / android-NDEF POS (sibling project).
// A worktree has no keystore: point at the main checkout's directory by path (never copy the files),
// -PreleaseKeystoreDir=<dir> or ORG_GRADLE_PROJECT_releaseKeystoreDir=<dir>.
val androidInitNdefDir = providers.gradleProperty("releaseKeystoreDir").orNull?.let { file(it) }
    ?: rootProject.file("../Android-init-NDEF")
if (providers.gradleProperty("releaseKeystoreDir").isPresent && !androidInitNdefDir.resolve("keystore.properties").exists()) {
    throw GradleException("releaseKeystoreDir has no keystore.properties: $androidInitNdefDir")
}
val keystorePropertiesFile = androidInitNdefDir.resolve("keystore.properties")
val remotePwaUpdate = providers.gradleProperty("remotePwaUpdate").orNull == "true"
// Internal OTA test builds only (debug/release with -PremotePwaUpdate=true): point the daemon at a
// local stub instead of production, e.g. -PotaManifestUrl=http://10.0.2.2:8765/app/update.json.
// A stub URL also enables cleartext to 10.0.2.2 only, in debug (src/otaLocalStub/res).
val otaManifestUrl = providers.gradleProperty("otaManifestUrl").orNull ?: "https://beamio.ca/app/update.json"
val otaBundleBase = providers.gradleProperty("otaBundleBase").orNull ?: "https://beamio.ca/app/"
val otaCheckIntervalMs = providers.gradleProperty("otaCheckIntervalMs").orNull?.toLong() ?: (15L * 60L * 1000L)
val otaLocalStub = providers.gradleProperty("otaManifestUrl").orNull != null
// QA only: one Ed25519 test public key (raw 32 bytes, base64) for end-to-end signed OTA acceptance against a local
// stub. Allowed only with -PotaManifestUrl and -PremotePwaUpdate=true, never for store artifacts; a release built with
// it is signed with the debug certificate and labelled "-otaqa". Formal builds have an empty QA key.
val otaQaPublicKey: String = providers.gradleProperty("otaQaPublicKey").orNull?.trim() ?: ""
if (otaQaPublicKey.isNotEmpty()) {
    if (!otaLocalStub || !remotePwaUpdate) throw GradleException("-PotaQaPublicKey needs -PotaManifestUrl and -PremotePwaUpdate=true (QA stub builds only).")
    if (!Regex("^[A-Za-z0-9+/]{43}=$").matches(otaQaPublicKey)) throw GradleException("-PotaQaPublicKey must be a base64 raw Ed25519 public key (32 bytes).")
    if (gradle.startParameter.taskNames.any { it.contains("store", ignoreCase = true) || it.contains("bundle", ignoreCase = true) }) {
        throw GradleException("-PotaQaPublicKey is never allowed for store or bundle artifacts.")
    }
}
// Native key import binding (spec 25.25): the SDK side compiles only against the unreleased 0.2.7 line.
// Default: src/nativekeyNone (no native key, import unavailable, shell gate passes everything through).
val chatSdkNativeKey = providers.gradleProperty("chatSdkNativeKey").orNull == "true"
// Release rule (2026-11-17): a release or store build must mount BeamioShellRecord, i.e. use the nativekeySdk line. A build without it
// is a degraded shell, and no degraded shell may be published (project rule). The check runs at configuration for any requested
// release-type task, so no package is produced by the default (nativekeyNone) variant.
// Artifact-level check (2026-11-17): the release APK or AAB must contain the native-key binding that mounts BeamioShellRecord.
// The check reads the built artifact's dex entries and looks for the binding's class descriptor. R8 keeps the class under its own
// name (-keep rule above), so the descriptor is present only when the class is in the package. Each task checks its own output.
fun checkNativeKeyDex(artifact: File) {
    if (!artifact.isFile) throw GradleException("release artifact missing: ${artifact.path}")
    val needle = "com/beamio/app/nativekey/NativeKeySdkBinding".toByteArray(Charsets.UTF_8)
    fun contains(hay: ByteArray, pat: ByteArray): Boolean {
        outer@ for (i in 0..hay.size - pat.size) {
            for (j in pat.indices) if (hay[i + j] != pat[j]) continue@outer
            return true
        }
        return false
    }
    var dexCount = 0
    var hits = 0
    ZipFile(artifact).use { zf ->
        for (e in Collections.list(zf.entries())) {
            if (!e.name.endsWith(".dex")) continue
            dexCount++
            if (contains(zf.getInputStream(e).use { it.readBytes() }, needle)) hits++
        }
    }
    if (dexCount == 0 || hits == 0) {
        throw GradleException("release artifact ${artifact.name} lacks NativeKeySdkBinding (dex entries=$dexCount): BeamioShellRecord is not mounted (release rule 2026-11-17)")
    }
}
val verifyNativeKeyMountedApk = tasks.register("verifyNativeKeyMountedApk") {
    doLast { checkNativeKeyDex(layout.buildDirectory.file("outputs/apk/release/app-release.apk").get().asFile) }
}
val verifyNativeKeyMountedAab = tasks.register("verifyNativeKeyMountedAab") {
    doLast { checkNativeKeyDex(layout.buildDirectory.file("outputs/bundle/release/app-release.aab").get().asFile) }
}
tasks.matching { it.name == "assembleRelease" }.configureEach { finalizedBy(verifyNativeKeyMountedApk) }
tasks.matching { it.name == "bundleRelease" }.configureEach { finalizedBy(verifyNativeKeyMountedAab) }

// The check looks at the whole task graph of this project, not only the requested names: a bundle or assemble aggregate
// (bundle, assemble, build, install, publish, package, check) reaches the release variant too, so it counts as release-like.
gradle.taskGraph.whenReady {
    val releaseLike = allTasks.any { t ->
        t.project == project && (
            Regex("(?i)(release|store)").containsMatchIn(t.name) ||
                Regex("^(assemble|bundle|build|install|publish|package|check|lint)$").matches(t.name)
            )
    }
    if (releaseLike && !chatSdkNativeKey) {
        throw GradleException("release/store artifact tasks require -PchatSdkNativeKey=true (BeamioShellRecord must be mounted; release rule 2026-11-17).")
    }
}
// the chat SDK version and its AAR SHA-256 are pinned in app/chat-sdk.lock. -PchatSdkVersion may be omitted;
// when given it must equal the lock. verifyChatSdkLock checks the resolved AAR bytes on every build.
val chatSdkLock: Map<String, String> = file("chat-sdk.lock").takeIf { it.isFile }?.readLines()
    ?.filter { it.isNotBlank() && !it.trimStart().startsWith("#") && it.contains("=") }
    ?.associate { it.substringBefore("=").trim() to it.substringAfter("=").trim() }
    ?: throw GradleException("app/chat-sdk.lock missing: the chat SDK must be pinned.")
val chatSdkLockedVersion: String = chatSdkLock["chat_sdk_version"]?.takeIf { it.isNotBlank() }
    ?: throw GradleException("app/chat-sdk.lock has no chat_sdk_version")
val chatSdkLockedSha: String = chatSdkLock["chat_sdk_aar_sha256"]?.lowercase()?.takeIf { Regex("^[0-9a-f]{64}$").matches(it) }
    ?: throw GradleException("app/chat-sdk.lock has no valid chat_sdk_aar_sha256")
val chatSdkLockedQa = chatSdkLock["chat_sdk_qa"] == "true"
val chatSdkVersion: String = providers.gradleProperty("chatSdkVersion").orNull?.also {
    if (it != chatSdkLockedVersion) throw GradleException("-PchatSdkVersion=$it is not the pinned $chatSdkLockedVersion in app/chat-sdk.lock (update the lock in its own reviewed commit).")
} ?: chatSdkLockedVersion
// QA write guard (PWA integration, 2026-11-14): -PqaWriteGuard=true turns it on in debug builds only.
// Release and store builds always get false.
val qaWriteGuard = providers.gradleProperty("qaWriteGuard").orNull == "true"
// Plan N page record + legacy PGP migration (spec r3ay 25.52D). (2026-11-14, spec r3cx §25.52AZ.4): the
// window.BeamioShellRecord channel is part of release and store builds. Debug builds have it too unless -PplanN=false.
val planN = providers.gradleProperty("planN").orNull != "false"
// the sensitive CashTreesAndroid methods live on window.BeamioShell / window.BeamioChat
// (spec §25.52AA.11). CashTreesJsBridgeLegacy re-exposes them on CashTreesAndroid for pages that have not switched.
// Defaults: false in every build type (any iframe could reach chatModuleCommand /
// chatModuleSignResponse through it); debug/debugqa and release can still opt in with -PlegacySensitiveBridge=true for a QA
// probe; store is always false (no override). A build with it on is a QA artifact, never a release package (DR.3).
// The 0.53.x page prefers window.BeamioChat and only falls back to CashTreesAndroid when BeamioChat is missing.
val legacySensitiveBridgeProp = providers.gradleProperty("legacySensitiveBridge").orNull
val legacyDebug = legacySensitiveBridgeProp == "true"
val legacyRelease = legacySensitiveBridgeProp == "true"
// QA native evidence page (§25.37.4 A5): -PchatQaHooks compiles src/qaHooks into debug builds only and swaps in
// src/qaHooksDebug/AndroidManifest.xml. Release and store never get it; scripts/verify-android-no-qa-hooks.sh checks the APKs.
val chatQaHooks = providers.gradleProperty("chatQaHooks").isPresent
// QA exception (2026-11-22): the only debugqa exception for -PchatQaHooks (t168 read-fault package). Defined next to chatQaHooks.
val t168ReadFaultAllowed = providers.gradleProperty("allowQaHooksOnDebugqa").orNull == "t168-read-fault"
if (providers.gradleProperty("allowQaHooksOnDebugqa").isPresent && !t168ReadFaultAllowed) {
    throw GradleException("-PallowQaHooksOnDebugqa only accepts the value t168-read-fault.")
}
if (chatQaHooks && !chatSdkNativeKey) throw GradleException("-PchatQaHooks needs the native-key SDK line (-PchatSdkNativeKey=true).")
// QA only: debug builds use release-like cleartext rules so the chat SDK can reach node IPs over HTTP.
val qaCleartextNsc = providers.gradleProperty("qaCleartextNsc").orNull == "true"
// AH.6 item 3 (spec r3ck §25.52AM.2): -PqaReleaseVariant=true builds the release type unchanged except for
// applicationId com.beamio.app.t168r and the debug signing key, so it installs beside t168; androidTest then targets it.
// No QA switch may be combined with it.
val qaReleaseVariant = providers.gradleProperty("qaReleaseVariant").orNull == "true"
if (qaReleaseVariant && (chatQaHooks || qaWriteGuard || qaCleartextNsc)) {
    throw GradleException("-PqaReleaseVariant must not be combined with any QA switch (chatQaHooks, qaWriteGuard, qaCleartextNsc).")
}
// Expected embedded zip SHA-256 for BuildConfig.PWA_ZIP_SHA256 comes from pwa-embed.lock (written with
// the freeze manifest), never from the zip itself (same-sha-gate.md section 3 item 1). verifyPwaEmbedLock
// checks the zip against the lock on every build; a missing lock leaves the value blank, which the gate
// rejects and the store startup check treats as "load nothing".
val pwaEmbedLock: Map<String, String> = file("pwa-embed.lock").takeIf { it.isFile }?.readLines()
    ?.filter { it.isNotBlank() && !it.trimStart().startsWith("#") && it.contains("=") }
    ?.associate { it.substringBefore("=").trim() to it.substringAfter("=").trim() }
    ?: emptyMap()
val embeddedPwaZipSha256: String = pwaEmbedLock["zip_sha256"]?.lowercase()
    ?.takeIf { Regex("^[0-9a-f]{64}$").matches(it) } ?: ""
// build-time identity of the embedded package, so a fast cold start can
// seed bridge trust without reading the APK ZIP. PWA_ZIP_VER is the lock's zip_ver (plain x.y.z only, else "").
// PWA_CONTENT_SHA256 is the content digest of src/main/assets/SilentPassUI.zip computed exactly like the runtime
// EmbeddedPwaBundleStore.contentLines after EmbeddedPwaZip.unzip: every non-directory entry (last one wins), __MACOSX/
// removed, the two .loaded-* marker names skipped, one line "path\u0000sha256(contents)" per file, sorted, each line
// plus "\n", SHA-256. It is computed only when every byte of the ZIP hashes to the lock's zip_sha256 (else ""), and
// verifyPwaContentConstant (after verifyPwaEmbedLock) fails the build when it is missing.
val embeddedPwaZipVer: String = pwaEmbedLock["zip_ver"]
    ?.takeIf { Regex("^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})$").matches(it) } ?: ""
val embeddedPwaContentSha256: String = run {
    val zip = file("src/main/assets/SilentPassUI.zip")
    if (!zip.isFile || embeddedPwaZipSha256.isEmpty()) return@run ""
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    val bytes = zip.readBytes()
    if (hex(MessageDigest.getInstance("SHA-256").digest(bytes)) != embeddedPwaZipSha256) return@run ""
    val entries = LinkedHashMap<String, String>()
    ZipInputStream(ByteArrayInputStream(bytes)).use { zis ->
        var e = zis.nextEntry
        while (e != null) {
            if (!e.isDirectory) {
                val name = File(e.name).normalize().invariantSeparatorsPath
                if (name.startsWith("../") || name == ".." || File(name).isAbsolute) {
                    throw GradleException("SilentPassUI.zip entry escapes the bundle: ${e.name}")
                }
                entries[name] = hex(MessageDigest.getInstance("SHA-256").digest(zis.readBytes()))
            }
            zis.closeEntry()
            e = zis.nextEntry
        }
    }
    val markers = setOf(".loaded-sha256", ".loaded-content-sha256")
    val lines = entries.filterKeys { k -> k != "__MACOSX" && !k.startsWith("__MACOSX/") && k.substringAfterLast('/') !in markers }
        .map { (k, v) -> "$k\u0000$v" }
        .sorted()
    val all = MessageDigest.getInstance("SHA-256")
    lines.forEach { all.update((it + "\n").toByteArray(Charsets.UTF_8)) }
    hex(all.digest())
}
// Spec r3np §25.52Y.38 item 2 (a) / r3nq §25.52Y.41 item 3: the embedded PWA's capability bits (e.g. the walletCredential bit)
// come only from the build manifest handed to the PWA version gate (-PpwaFreezeManifest or -PpwaQaManifest, with
// -PpwaUnreleasedTest=true): its "capabilities" array of strings, bound to its zip_sha256, which must equal pwa-embed.lock.
// No other source: not the page, not a shell constant, not a Gradle switch. Without such a manifest the list is empty, so
// walletCredential and the shellRecordRead W-field read-back answer not_trusted.
val pwaCapabilities: List<String> = run {
    val unreleased = providers.gradleProperty("pwaUnreleasedTest").orNull == "true"
    val freezePath = providers.gradleProperty("pwaFreezeManifest").orNull
    val manifestPath = if (unreleased) freezePath ?: providers.gradleProperty("pwaQaManifest").orNull else null
    val manifestFile = manifestPath?.let { file(it) }?.takeIf { it.isFile } ?: return@run emptyList()
    // The manifest file itself must be the one the sync script recorded in pwa-embed.lock (freeze_manifest_sha256 or
    // qa_manifest_sha256), so an edited copy cannot add bits.
    val lockedManifestSha = pwaEmbedLock[if (freezePath != null) "freeze_manifest_sha256" else "qa_manifest_sha256"]?.lowercase()
    val manifestFileSha = MessageDigest.getInstance("SHA-256").digest(manifestFile.readBytes()).joinToString("") { "%02x".format(it) }
    @Suppress("UNCHECKED_CAST")
    val manifest = JsonSlurper().parse(manifestFile) as Map<String, Any?>
    val raw = manifest["capabilities"] ?: return@run emptyList()
    if (lockedManifestSha == null || manifestFileSha != lockedManifestSha) {
        throw GradleException("manifest $manifestFile declares capabilities but is not the manifest file recorded in pwa-embed.lock")
    }
    val list = (raw as? List<*>)?.map { it as? String ?: throw GradleException("manifest capabilities must be strings: $manifestFile") }
        ?: throw GradleException("manifest capabilities must be an array: $manifestFile")
    list.forEach { if (!Regex("^[a-z0-9][a-z0-9.-]{0,63}$").matches(it)) throw GradleException("bad capability name in $manifestFile") }
    val sha = manifest["zip_sha256"]?.toString()?.lowercase()
    if (embeddedPwaZipSha256.isEmpty() || sha != embeddedPwaZipSha256) {
        throw GradleException("manifest $manifestFile declares capabilities but its zip_sha256 is not the pwa-embed.lock zip_sha256")
    }
    list.distinct().sorted()
}
// bits from a QA candidate manifest are QA only. The store build type takes capability bits only from a freeze
// manifest (which, per §25.52Y.43 item 3, carries them only with an acceptance_ref); from a QA manifest it gets none.
val pwaCapabilitiesFromFreeze = providers.gradleProperty("pwaFreezeManifest").orNull != null
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystorePropertiesFile.inputStream().use { keystoreProperties.load(it) }
}

android {
    namespace = "com.beamio.app"
    // AH.6 item 3: instrumentation runs against the release type only for the t168r variant.
    if (qaReleaseVariant) testBuildType = "release"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        // Consumer website APK and store id. The QA ids (t168, t168r) only for the QA variants (debugqa forced below, t168r above).
        applicationId = if (qaReleaseVariant) "com.beamio.app.t168r" else "com.beamio.app"
        minSdk = 24
        targetSdk = 36
        versionCode = 191
        versionName = "1.0.173"

        // t168r (AH.6 item 3): a plain framework Instrumentation, since the minified release app lacks androidx.tracing.
        testInstrumentationRunner = if (qaReleaseVariant) "com.beamio.app.ah6.Ah6BridgeInstrumentation" else "androidx.test.runner.AndroidJUnitRunner"

        // SHA-256 of the bundled SilentPassUI.zip; the store bootstrap refuses to load anything else.
        // With -PpwaFreezeManifest the preBuild gate already requires this file to equal the frozen zip_sha256.
        buildConfigField("String", "PWA_ZIP_SHA256", "\"$embeddedPwaZipSha256\"")
        // content digest and version of that same package (build-time constants, see above).
        buildConfigField("String", "PWA_CONTENT_SHA256", "\"$embeddedPwaContentSha256\"")
        buildConfigField("String", "PWA_ZIP_VER", "\"$embeddedPwaZipVer\"")
        // QA-only OTA test key (empty in every formal build; see otaQaPublicKey above).
        buildConfigField("String", "OTA_QA_PUBLIC_KEY", "\"$otaQaPublicKey\"")
        // §25.52Y.38 item 2 (a): capability bits of that same package and the zip_sha256 they are bound to ("" when none).
        buildConfigField("String", "PWA_CAPABILITIES", "\"${pwaCapabilities.joinToString(",")}\"")
        buildConfigField("String", "PWA_CAPABILITIES_ZIP_SHA256", "\"${if (pwaCapabilities.isEmpty()) "" else embeddedPwaZipSha256}\"")
    }
    buildFeatures {
        buildConfig = true
    }
    // Every build type carries the label; only debugqa sets it (HD.2: products are marked QA).
    defaultConfig.buildConfigField("String", "QA_BUILD_LABEL", "\"\"")
    dependenciesInfo {
        // The website APK must rebuild byte for byte from its commit. The dependency block AGP adds to an APK's signing
        // block is encrypted afresh on every build, so it is left out of APKs. The store AAB keeps it (Play uses it); the
        // store universal APK is produced from the bundle and is unaffected.
        includeInApk = false
        includeInBundle = true
    }
    packaging {
        // bcprov, bcutil and bcpg each ship META-INF/LICENSE.md (same BC MIT text); keep one copy.
        resources { pickFirsts += setOf("META-INF/LICENSE.md") }
    }
    sourceSets {
        // Manifest v2 golden-vector runner shared by the JVM unit tests and the instrumented test (API 24–32).
        getByName("test").let { it.java.directories.add("src/sharedTest/java"); it.kotlin.directories.add("src/sharedTest/java") }
        getByName("androidTest").let { it.java.directories.add("src/sharedTest/java"); it.kotlin.directories.add("src/sharedTest/java") }
        // Remote PWA update code (manifest, download, staging) only in non-store build types.
        getByName("debug").let { it.java.directories.add("src/ota/java"); it.kotlin.directories.add("src/ota/java") }
        getByName("release").let { it.java.directories.add("src/ota/java"); it.kotlin.directories.add("src/ota/java") }
        maybeCreate("store").let { it.java.directories.add("src/noota/java"); it.kotlin.directories.add("src/noota/java") }
        // the QA write guard lives in src/debug; release and store get a no-op stub with the same calls.
        getByName("release").let { it.java.directories.add("src/qaGuardStub/java"); it.kotlin.directories.add("src/qaGuardStub/java") }
        maybeCreate("store").let { it.java.directories.add("src/qaGuardStub/java"); it.kotlin.directories.add("src/qaGuardStub/java") }
        getByName("debug").res.directories.add(if (qaCleartextNsc) "src/qaCleartextNsc/res" else if (otaLocalStub) "src/otaLocalStub/res" else "src/otaDefaultNsc/res")
        if (chatQaHooks) getByName("debug").let {
            it.java.directories.add("src/qaHooks/java"); it.kotlin.directories.add("src/qaHooks/java")
            it.manifest.srcFile("src/qaHooksDebug/AndroidManifest.xml")
        }
        // Spec §25.52HD (HD.1): debugqa is the debug build under the approved name; same QA code and manifest as debug.
        maybeCreate("debugqa").let {
            for (d in listOf("src/debug/java", "src/ota/java")) { it.java.directories.add(d); it.kotlin.directories.add(d) }
            it.manifest.srcFile("src/debug/AndroidManifest.xml")
            it.res.directories.add(if (qaCleartextNsc) "src/qaCleartextNsc/res" else "src/otaDefaultNsc/res")
            // QA exception: the t168 read-fault package only (-PchatQaHooks with -PallowQaHooksOnDebugqa=t168-read-fault): the independent
            // qaReadFault source set and its manifest; the QA evidence page is NOT compiled here.
            if (chatQaHooks && t168ReadFaultAllowed) {
                it.java.directories.add("src/qaReadFault/java"); it.kotlin.directories.add("src/qaReadFault/java")
                it.manifest.srcFile("src/qaReadFault/AndroidManifest.xml")
            }
        }
        val nativeKeyDir = if (chatSdkNativeKey) "src/nativekeySdk/java" else "src/nativekeyNone/java"
        getByName("main").let { it.java.directories.add(nativeKeyDir); it.kotlin.directories.add(nativeKeyDir) }
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            create("release") {
                val storeRel = keystoreProperties.getProperty("storeFile")
                storeFile = androidInitNdefDir.resolve(storeRel)
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        // Remote PWA update (OTA) is off by default in every build type. Only an explicit internal test
        // build of debug/release passes -PremotePwaUpdate=true. The `store` build type below is the store
        // artifact: OTA is always off and the remote-install code (src/ota/java) is not compiled.
        debug {
            buildConfigField("boolean", "QA_WRITE_GUARD", qaWriteGuard.toString())
            buildConfigField("boolean", "PLAN_N", planN.toString())
            buildConfigField("boolean", "LEGACY_SENSITIVE_BRIDGE", legacyDebug.toString()) // default false; opt-in QA probe only
            buildConfigField("boolean", "REMOTE_PWA_UPDATE", remotePwaUpdate.toString())
            buildConfigField("String", "OTA_MANIFEST_URL", "\"$otaManifestUrl\"")
            buildConfigField("String", "OTA_BUNDLE_BASE", "\"$otaBundleBase\"")
            buildConfigField("long", "OTA_CHECK_INTERVAL_MS", "${otaCheckIntervalMs}L")
            // Same cert as the installed release so install-over does not
            // require uninstall. Device wallet data stays in place.
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        release {
            buildConfigField("boolean", "QA_WRITE_GUARD", "false")
            buildConfigField("boolean", "PLAN_N", "true") // plan N channel in release/store
            buildConfigField("boolean", "LEGACY_SENSITIVE_BRIDGE", legacyRelease.toString()) // default false
            buildConfigField("boolean", "REMOTE_PWA_UPDATE", remotePwaUpdate.toString())
            buildConfigField("String", "OTA_MANIFEST_URL", "\"$otaManifestUrl\"")
            buildConfigField("String", "OTA_BUNDLE_BASE", "\"$otaBundleBase\"")
            buildConfigField("long", "OTA_CHECK_INTERVAL_MS", "${otaCheckIntervalMs}L")
            // R8：缩小体积 + 生成 mapping；AGP 8.5+ 会将 mapping 打入 AAB，Play 可自动去混淆崩溃栈
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (qaReleaseVariant || otaQaPublicKey.isNotEmpty()) {
                // QA stub builds (test OTA key) are never signed with the upload key.
                signingConfig = signingConfigs.getByName("debug")
                if (otaQaPublicKey.isNotEmpty()) versionNameSuffix = "-otaqa"
            } else if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        // Spec §25.52HD.1/HD.2 (written approval): the internal QA build named `debugqa`, only for the
        // Samsung S25, application id com.beamio.app.t168 (forced below), debug key only (never the store certificate), with the
        // QA chat SDK of app/chat-sdk.lock and the QA manifest's capability bits. It declares nothing by itself: per HD.3 a
        // capability such as the native-keys bit comes only from the SDK build. Not for release, store or anyone outside.
        create("debugqa") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            isDebuggable = true
            // Naming rule: versionName stays pure dotted digits; the QA label is carried by QA_BUILD_LABEL, not the name.
            signingConfig = signingConfigs.getByName("debug")
            buildConfigField("String", "QA_BUILD_LABEL", "\"debugqa\"")
        }
        create("store") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            buildConfigField("boolean", "REMOTE_PWA_UPDATE", "false")
            buildConfigField("boolean", "QA_WRITE_GUARD", "false")
            buildConfigField("boolean", "PLAN_N", "true") // plan N channel in release/store
            buildConfigField("boolean", "LEGACY_SENSITIVE_BRIDGE", "false") // store never re-exposes them
            // initWith copied the OTA fields from release: blank them so no update URL reaches store.
            buildConfigField("String", "OTA_MANIFEST_URL", "\"\"")
            buildConfigField("String", "OTA_BUNDLE_BASE", "\"\"")
            buildConfigField("long", "OTA_CHECK_INTERVAL_MS", "0L")
            // QA-manifest capability bits never reach a store build.
            if (!pwaCapabilitiesFromFreeze) {
                buildConfigField("String", "PWA_CAPABILITIES", "\"\"")
                buildConfigField("String", "PWA_CAPABILITIES_ZIP_SHA256", "\"\"")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    testOptions {
        // Local unit tests call android.util.Log through EmbeddedPwaBundleStore.
        unitTests.isReturnDefaultValues = true
        // Manifest v2 golden vectors (TEST ONLY, outside the repository): -PotaVectorsDir=<dir with vectors.json, zips/>
        // and -PotaGoldenZip=<frozen SilentPassUI-0.53.48.zip>. Without them the vector test is skipped.
        unitTests.all { t ->
            providers.gradleProperty("otaVectorsDir").orNull?.let { t.systemProperty("beamio.otaVectorsDir", it) }
            providers.gradleProperty("otaGoldenZip").orNull?.let { t.systemProperty("beamio.otaGoldenZip", it) }
        }
    }
}

/**
 * The shell serves the bundled PWA from the asset-loader root, so the zip must
 * come from `build:embedded` (`PUBLIC_URL=/`). A web build (homepage `/app`)
 * loads `/app/static/...` and shows only a broken icon (2026-11-05 test build).
 * Same rule as EmbeddedPwaBundleStore.indexHtmlUsesEmbeddedAssetPaths and
 * scripts/checkEmbeddedPwaZip.sh.
 */
val verifyEmbeddedPwaZip by tasks.registering {
    group = "verification"
    description = "Fail when assets/SilentPassUI.zip is a web build (/app/ asset paths)"
    val zipFile = layout.projectDirectory.file("src/main/assets/SilentPassUI.zip").asFile
    inputs.file(zipFile).withPropertyName("embeddedPwaZip")
    doLast {
        ZipFile(zipFile).use { zip ->
            val entry = zip.getEntry("index.html")
                ?: throw GradleException("$zipFile has no index.html at the zip root")
            val html = zip.getInputStream(entry).bufferedReader().readText()
            val webBuildRefs = Regex("""\b(?:src|href)\s*=\s*["']?(/app/[^"'\s>]*)""", RegexOption.IGNORE_CASE)
                .findAll(html).map { it.groupValues[1] }.take(3).toList()
            if (webBuildRefs.isNotEmpty()) {
                throw GradleException(
                    "$zipFile is a web build: index.html loads ${webBuildRefs.joinToString()}. " +
                        "Rebuild SilentPassUI with build:embedded (PUBLIC_URL=/).",
                )
            }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyEmbeddedPwaZip) }

/**
 * Same-SHA build gate: assets/SilentPassUI.zip must equal pwa-embed.lock (zip_sha256, update.json ver),
 * and the lock must equal pwa-freeze-manifest.json when that copy is present. No skip property.
 */
val verifyPwaEmbedLock by tasks.registering(Exec::class) {
    group = "verification"
    description = "Fail unless the embedded PWA zip is the one recorded in pwa-embed.lock"
    val gate = rootProject.file("scripts/verify-android-pwa-embed-lock.sh")
    val appDir = projectDir
    inputs.file(layout.projectDirectory.file("src/main/assets/SilentPassUI.zip"))
    outputs.upToDateWhen { false }
    doFirst {
        if (!gate.isFile) throw GradleException("PWA embed lock gate missing: $gate. Packaging refused.")
        commandLine(gate.path, "--app-dir", appDir.path)
    }
}
tasks.named("preBuild") { dependsOn(verifyPwaEmbedLock) }
// the content constant must exist whenever the lock exists (it is derived only from a ZIP whose every
// byte matches the lock's zip_sha256); otherwise a fast cold start could not seed trust and the build is refused.
val verifyPwaContentConstant by tasks.registering {
    mustRunAfter(verifyPwaEmbedLock)
    doLast {
        if (embeddedPwaZipSha256.isNotEmpty() && embeddedPwaContentSha256.isEmpty()) {
            throw GradleException("PWA_CONTENT_SHA256 missing: src/main/assets/SilentPassUI.zip does not match pwa-embed.lock zip_sha256")
        }
        println("{\"gate\":\"pwa-content-constant\",\"result\":\"PASS\",\"zip_ver\":\"$embeddedPwaZipVer\",\"content_sha256\":\"${embeddedPwaContentSha256.take(8)}\"}")
    }
}
tasks.named("preBuild") { dependsOn(verifyPwaContentConstant) }

/**
 * PWA version gate (since 2026-11-11): the shell must embed the latest
 * released PWA (live https://beamio.ca/app/update.json, same ZIP bytes) or a
 * strictly higher version that is an approved release or an explicit
 * unreleased test. Runs scripts/verify-shell-pwa-version.sh on every build;
 * a missing script or any failure stops the build.
 *   Approved higher release: -PpwaApprovedVer=X -PpwaApprovedSha=HEX -PpwaApproval="record"
 *   Local unreleased test:   -PpwaUnreleasedTest=true -PpwaFreezeManifest=<pwa-freeze/<ver>.json>
 *                            (versionName gets "-pwa-unreleased-test"). Same rule as the unified sync
 *                            script: an unreleased PWA goes in only as the frozen build in the
 *                            manifest (status "frozen", embedded ZIP sha256 and version equal to
 *                            its zip_sha256 and version), checked before the shared checker runs.
 * QA candidate (NOT FROZEN): -PpwaUnreleasedTest=true -PpwaQaManifest=<qa manifest JSON>
 *                            (status "qa-candidate", not_frozen true, freeze_kind "qa-candidate-not-frozen"; the
 *                            embedded ZIP sha256 and version must equal its zip_sha256 and version). Verdict QA only.
 */
val pwaUnreleasedTest = providers.gradleProperty("pwaUnreleasedTest").orNull == "true"
val pwaFreezeManifest = providers.gradleProperty("pwaFreezeManifest").orNull
val pwaQaManifest = providers.gradleProperty("pwaQaManifest").orNull
if (pwaUnreleasedTest) {
    android.defaultConfig.versionNameSuffix = "-pwa-unreleased-test"
}
// Gate pins (ORDER 2026-11-21T2335Z): the shared PWA gate scripts must be byte-identical to the pinned SHA-256 values in
// scripts/gate-pins.sha256 before any PWA gate runs. A mismatch refuses the build.
val verifyPwaGatePins by tasks.registering {
    group = "verification"
    description = "Fail unless the PWA gate scripts match scripts/gate-pins.sha256"
    doFirst {
        val pins = rootProject.file("scripts/gate-pins.sha256")
        if (!pins.isFile) throw GradleException("gate pins missing: $pins (build refused)")
        var checked = 0
        pins.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size != 2) throw GradleException("bad gate pin line: $line")
            val want = parts[0].lowercase()
            val name = parts[1]
            val f = rootProject.file("scripts/$name")
            if (!f.isFile) throw GradleException("gate script missing: $f (build refused)")
            val got = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }
            if (got != want) throw GradleException("gate script $name sha256 $got is not the pinned $want (build refused)")
            checked++
        }
        if (checked == 0) throw GradleException("gate pins file lists no scripts (build refused)")
    }
}

val verifyShellPwaVersion by tasks.registering {
    dependsOn(verifyPwaGatePins)
    group = "verification"
    description = "Fail unless the embedded PWA is the released one, an approved higher release, or a marked unreleased test"
    val gate = rootProject.file("scripts/verify-shell-pwa-version.sh")
    val appDir = projectDir
    outputs.upToDateWhen { false }
    doFirst {
        if (!gate.isFile) {
            throw GradleException("PWA version gate missing: $gate. Packaging refused (export scripts/verify-shell-pwa-version.sh with the shell).")
        }
        val args = mutableListOf(gate.path, "android-prebuild", "--app-dir", appDir.path)
        val approvedVer = providers.gradleProperty("pwaApprovedVer").orNull
        if (approvedVer != null) {
            args += listOf(
                "--approved-ver", approvedVer,
                "--approved-sha", providers.gradleProperty("pwaApprovedSha").orNull ?: "",
                "--approval", providers.gradleProperty("pwaApproval").orNull ?: "",
            )
        }
        if (pwaUnreleasedTest && pwaQaManifest != null) {
            if (pwaFreezeManifest != null) {
                throw GradleException("use either -PpwaFreezeManifest or -PpwaQaManifest, not both")
            }
            val qaPath = pwaQaManifest ?: throw GradleException("-PpwaQaManifest is empty")
            val qaFile = file(qaPath)
            if (!qaFile.isFile) throw GradleException("QA manifest not found: $qaFile")
            @Suppress("UNCHECKED_CAST")
            val qa = JsonSlurper().parse(qaFile) as Map<String, Any?>
            val qaVer = qa["version"]?.toString()
            val qaSha = qa["zip_sha256"]?.toString()?.lowercase()
            if (qa["status"] != "qa-candidate" || qa["not_frozen"] != true || qa["freeze_kind"] != "qa-candidate-not-frozen" ||
                qaVer.isNullOrBlank() || qaSha.isNullOrBlank()) {
                throw GradleException("QA manifest $qaFile is not a QA candidate (status qa-candidate, not_frozen true, freeze_kind qa-candidate-not-frozen).")
            }
            val qaZip = File(appDir, "src/main/assets/SilentPassUI.zip")
            val qaZipSha = MessageDigest.getInstance("SHA-256").digest(qaZip.readBytes())
                .joinToString("") { "%02x".format(it) }
            if (qaZipSha != qaSha) {
                throw GradleException("Embedded SilentPassUI.zip sha256 $qaZipSha is not the QA zip_sha256 $qaSha in $qaFile.")
            }
            val qaZipVer = ZipFile(qaZip).use { z ->
                val e = z.getEntry("update.json") ?: throw GradleException("Embedded SilentPassUI.zip has no update.json")
                @Suppress("UNCHECKED_CAST")
                ((JsonSlurper().parse(z.getInputStream(e)) as Map<String, Any?>)["ver"])?.toString()
            }
            if (qaZipVer != qaVer) {
                throw GradleException("Embedded SilentPassUI.zip ver $qaZipVer is not the QA version $qaVer in $qaFile.")
            }
            args += listOf("--unreleased-test", "--qa-manifest", qaFile.path)
        } else if (pwaUnreleasedTest) {
            val manifestPath = pwaFreezeManifest
                ?: throw GradleException("-PpwaUnreleasedTest=true requires -PpwaFreezeManifest=<freeze manifest JSON> (only a frozen PWA may go into a shell before release approval).")
            val manifestFile = file(manifestPath)
            if (!manifestFile.isFile) throw GradleException("Freeze manifest not found: $manifestFile")
            @Suppress("UNCHECKED_CAST")
            val manifest = JsonSlurper().parse(manifestFile) as Map<String, Any?>
            val status = manifest["status"]?.toString()
            val frozenVer = manifest["version"]?.toString()
            val frozenSha = manifest["zip_sha256"]?.toString()?.lowercase()
            if (status != "frozen" || frozenVer.isNullOrBlank() || frozenSha.isNullOrBlank()) {
                throw GradleException("Freeze manifest $manifestFile is not usable: status=$status version=$frozenVer zip_sha256=$frozenSha (need status \"frozen\").")
            }
            val zip = File(appDir, "src/main/assets/SilentPassUI.zip")
            val zipSha = MessageDigest.getInstance("SHA-256").digest(zip.readBytes())
                .joinToString("") { "%02x".format(it) }
            if (zipSha != frozenSha) {
                throw GradleException("Embedded SilentPassUI.zip sha256 $zipSha is not the frozen zip_sha256 $frozenSha in $manifestFile.")
            }
            val zipVer = ZipFile(zip).use { z ->
                val e = z.getEntry("update.json") ?: throw GradleException("Embedded SilentPassUI.zip has no update.json")
                @Suppress("UNCHECKED_CAST")
                ((JsonSlurper().parse(z.getInputStream(e)) as Map<String, Any?>)["ver"])?.toString()
            }
            if (zipVer != frozenVer) {
                throw GradleException("Embedded SilentPassUI.zip ver $zipVer is not the frozen version $frozenVer in $manifestFile.")
            }
            args += listOf("--unreleased-test", "--freeze-manifest", manifestFile.path)
        } else if (pwaFreezeManifest != null || pwaQaManifest != null) {
            throw GradleException("-PpwaFreezeManifest and -PpwaQaManifest are only used with -PpwaUnreleasedTest=true.")
        }
        // Caller contract (ORDER 2026-11-21T2335Z items 2-4): run the gate, run the single-ZIP gate, then let
        // scripts/android-gate-decision.sh decide. Variant comes from the requested tasks; release accepts only exit 0.
        val gateRc = ProcessBuilder(args).directory(rootProject.projectDir).inheritIO().start().waitFor()
        val zipSha = MessageDigest.getInstance("SHA-256").digest(File(appDir, "src/main/assets/SilentPassUI.zip").readBytes())
            .joinToString("") { "%02x".format(it) }
        val singleZipRc = ProcessBuilder(
            rootProject.file("scripts/verify-android-single-zip.sh").path, "prebuild",
            "--app-dir", appDir.path, "--sha256", zipSha,
        ).directory(rootProject.projectDir).inheritIO().start().waitFor()
        val taskNames = gradle.startParameter.taskNames.joinToString(" ")
        val isRelease = listOf("Release", "Store", "Bundle").any { taskNames.contains(it, ignoreCase = true) }
        val variant = when {
            isRelease -> "release"
            taskNames.contains("Debugqa", ignoreCase = true) -> "debugqa"
            else -> "unknown"
        }
        val qaRequested = pwaUnreleasedTest && pwaQaManifest != null
        val decision = ProcessBuilder(
            rootProject.file("scripts/android-gate-decision.sh").path,
            "--variant", variant,
            "--qa-requested", if (qaRequested) "1" else "0",
            // debugqa t168 frozen wiring (2026-11-22): a frozen input is either -PpwaFreezeManifest or the shell-root
            // app/pwa-freeze-manifest.json (delegated freeze). Never with a QA manifest (the QA path keeps its frozen=0 contract).
            "--frozen-requested",
            if (pwaFreezeManifest != null || (!qaRequested && file("pwa-freeze-manifest.json").isFile)) "1" else "0",
            "--gate-rc", gateRc.toString(),
            "--singlezip-rc", singleZipRc.toString(),
        ).directory(rootProject.projectDir).inheritIO().start().waitFor()
        if (decision != 0) {
            throw GradleException("PWA gate refused (gate rc=$gateRc, single-ZIP rc=$singleZipRc, variant=$variant, qa=$qaRequested)")
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyShellPwaVersion) }

/**
 * Store gate (ota-integrity-plan.md, plan A): after R8, the `store` dex must hold no update URL,
 * update daemon, update-available event, capability bit or `applyEmbeddedPwaUpdate` bridge method.
 * No skip property: packaging a store APK or AAB always runs it, and a missing tool fails the build.
 */
val verifyStoreNoOta by tasks.registering(Exec::class) {
    group = "verification"
    description = "Fail if the store build dex contains any remote PWA update path"
    val gate = rootProject.file("scripts/verify-android-store-no-ota.sh")
    val dexDir = layout.buildDirectory.dir("intermediates/dex/store/minifyStoreWithR8")
    val sdkDir = androidComponents.sdkComponents.sdkDirectory
    outputs.upToDateWhen { false }
    doFirst {
        if (!gate.isFile) throw GradleException("Store OTA gate missing: $gate. Packaging refused.")
        if (!dexDir.get().asFile.isDirectory) throw GradleException("Store dex not found: ${dexDir.get().asFile}")
        environment("ANDROID_HOME", sdkDir.get().asFile.path)
        commandLine(gate.path, dexDir.get().asFile.path)
    }
}
tasks.configureEach {
    when (name) {
        "minifyStoreWithR8" -> finalizedBy(verifyStoreNoOta)
        "packageStore", "packageStoreBundle", "signStoreBundle" -> dependsOn(verifyStoreNoOta)
    }
}
afterEvaluate { verifyStoreNoOta.configure { dependsOn("minifyStoreWithR8") } }

/**
 * The resolved chat SDK AAR must have the SHA-256 pinned in app/chat-sdk.lock. Runs before every build; there is
 * no skip property. A QA-only lock (chat_sdk_qa=true) also blocks packaging a store APK or AAB.
 */
val verifyChatSdkLock by tasks.registering {
    group = "verification"
    description = "Fail unless the resolved chat SDK AAR matches app/chat-sdk.lock"
    outputs.upToDateWhen { false }
    val coordinate = "network.conet:chat:$chatSdkVersion@aar"
    val aarFiles = configurations.detachedConfiguration(dependencies.create(coordinate)).apply { isTransitive = false }
    doLast {
        val aar = aarFiles.singleFile
        val sha = MessageDigest.getInstance("SHA-256").digest(aar.readBytes()).joinToString("") { "%02x".format(it) }
        if (sha != chatSdkLockedSha) {
            throw GradleException("chat SDK $coordinate sha256 $sha != app/chat-sdk.lock $chatSdkLockedSha. Build refused.")
        }
        logger.lifecycle("{\"gate\":\"chat-sdk-lock\",\"result\":\"PASS\",\"version\":\"$chatSdkVersion\",\"aar_sha256\":\"$sha\",\"qa\":$chatSdkLockedQa}")
    }
}
val verifyChatSdkNotQaForStore by tasks.registering {
    group = "verification"
    description = "Fail packaging a store build with a QA-only chat SDK"
    doLast {
        if (chatSdkLockedQa) throw GradleException("app/chat-sdk.lock pins a QA-only chat SDK (chat_sdk_qa=true): store packaging refused.")
    }
}
tasks.matching { it.name == "preBuild" }.configureEach { dependsOn(verifyChatSdkLock) }
tasks.configureEach {
    if (name == "packageStore" || name == "packageStoreBundle" || name == "signStoreBundle") dependsOn(verifyChatSdkNotQaForStore)
}

/**
 * Spec §25.52HD: debugqa is the approved S25 QA build only. It cannot be combined with the release-QA probe
 * variant (whose id is t168r), and a debugqa product must not reach a release or store artifact.
 */
if (qaReleaseVariant && gradle.startParameter.taskNames.any { it.contains("debugqa", ignoreCase = true) }) {
    throw GradleException("debugqa is com.beamio.app.t168 only; -PqaReleaseVariant (t168r) cannot build it.")
}
// debugqa takes debug's QA code, manifest and NSC, but not the two optional debug add-ons (the 10.0.2.2 OTA stub NSC of
// -PotaManifestUrl and the -PchatQaHooks hooks): asking for debugqa with either switch fails instead of silently differing.
// QA exception (2026-11-22): one narrow exception for the t168 read-fault QA package only. -PallowQaHooksOnDebugqa=t168-read-fault
// lets debugqa take -PchatQaHooks; without it the exclusion above stays as before. The OTA stub is never allowed on debugqa.
// -PallowQaHooksOnDebugqa is meaningful only for a debugqa run; a release or store run never takes it.
if (providers.gradleProperty("allowQaHooksOnDebugqa").isPresent &&
    !gradle.startParameter.taskNames.any { it.contains("debugqa", ignoreCase = true) }) {
    throw GradleException("-PallowQaHooksOnDebugqa is only for a debugqa run (t168 read-fault package); it is refused for release and store.")
}
if ((otaLocalStub || chatQaHooks) && gradle.startParameter.taskNames.any { it.contains("debugqa", ignoreCase = true) } &&
    !(chatQaHooks && !otaLocalStub && t168ReadFaultAllowed)) {
    throw GradleException("debugqa does not take -PotaManifestUrl or -PchatQaHooks (debug-only test add-ons); build debugqa without them, or for the t168 read-fault package use -PchatQaHooks=true -PallowQaHooksOnDebugqa=t168-read-fault.")
}
val verifyDebugqaNotInReleaseOrStore by tasks.registering {
    group = "verification"
    description = "Fail a release or store packaging run that also asks for a debugqa product"
    doLast {
        if (gradle.startParameter.taskNames.any { it.contains("debugqa", ignoreCase = true) }) {
            throw GradleException("debugqa (HD.1 S25 internal QA) cannot be built in the same run as a release or store package.")
        }
    }
}
tasks.configureEach {
    if (name in setOf("packageRelease", "packageReleaseBundle", "signReleaseBundle", "packageStore", "packageStoreBundle", "signStoreBundle")) {
        dependsOn(verifyDebugqaNotInReleaseOrStore)
    }
}

// AGP 9 creates host unit tests for the test build type only; also run them for `store`
// (testStoreUnitTest proves the update daemon is not on the store classpath).
androidComponents {
    // HD.1: the debugqa application id is exactly com.beamio.app.t168.
    onVariants(selector().withBuildType("debugqa")) { variant ->
        variant.applicationId.set("com.beamio.app.t168")
        // QA exception: the read-fault package must be the t168 identity, never the personal main package.
        if (chatQaHooks && t168ReadFaultAllowed && variant.applicationId.get() != "com.beamio.app.t168") {
            throw GradleException("t168 read-fault package must use applicationId com.beamio.app.t168 (got ${variant.applicationId.get()})")
        }
    }
    // release also gets host unit tests (src/testRelease checks the release build shape).
    beforeVariants(selector().withBuildType("release")) { variant ->
        (variant as? com.android.build.api.variant.HasHostTestsBuilder)
            ?.hostTests?.get(com.android.build.api.variant.HostTestBuilder.UNIT_TEST_TYPE)
            ?.enable = true
    }
    beforeVariants(selector().withBuildType("store")) { variant ->
        (variant as? com.android.build.api.variant.HasHostTestsBuilder)
            ?.hostTests?.get(com.android.build.api.variant.HostTestBuilder.UNIT_TEST_TYPE)
            ?.enable = true
    }
}

/** Same as run-debug.sh — bypasses stale IDE applicationId (com.beamio.caehtrees). */
tasks.register<Exec>("launchDebug") {
    group = "application"
    description = "Install debug APK and start com.beamio.app.MainActivity"
    dependsOn("installDebug")
    commandLine(
        "adb",
        "shell",
        "am",
        "start",
        "-n",
        "com.beamio.app/com.beamio.app.MainActivity",
    )
}

dependencies {
    // Native Conet Chat module (listen / send / history / presence / hybrid signing).
    // Same role as the SwiftPM `chat-sdk-ios` package: https://github.com/CoNET-project/chat-sdk-android
    // Version pinned in app/chat-sdk.lock; the local maven dir comes from -PchatSdkLocalRepo (settings.gradle.kts).
    // The native-key line also needs -PchatSdkNativeKey=true.
    implementation("network.conet:chat:$chatSdkVersion")
    // Native route-key OpenPGP for call frames/control (off the WebView main thread).
    // BC 1.87 for every BC artifact (store runtime classpath resolves only 1.87; checked in the receipt).
    implementation("org.bouncycastle:bcpg-jdk18on:1.87")
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    implementation("org.bouncycastle:bcutil-jdk18on:1.87")
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity)
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.webkit:webkit:1.12.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // In-call video uplink (front camera → JPEG frames, same wire as iOS).
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    // Deferred deep link after Play install (merchant detail after onboarding)
    implementation("com.android.installreferrer:installreferrer:2.2")
    // Offline chat → FCM badge (replace app/google-services.json with Firebase Console export)
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)
    testImplementation(libs.junit)
    // Real org.json for local unit tests (android.jar only ships stubs).
    testImplementation("org.json:json:20240303")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

// QA hooks must never reach a release or store artifact: refuse the combination outright.
gradle.taskGraph.whenReady {
    if (chatQaHooks && allTasks.any { t -> t.project == project && Regex("(?i)(assemble|bundle|package)(release|store)").containsMatchIn(t.name) }) {
        throw GradleException("-PchatQaHooks is for debug QA builds only; release/store packaging refused.")
    }
}
