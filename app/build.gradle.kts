import groovy.json.JsonSlurper
import java.security.MessageDigest
import java.util.Properties
import java.util.zip.ZipFile

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
// Native key import binding (spec 25.25): the SDK side compiles only against the unreleased 0.2.7 line.
// Default: src/nativekeyNone (no native key, import unavailable, shell gate passes everything through).
val chatSdkNativeKey = providers.gradleProperty("chatSdkNativeKey").orNull == "true"
// PM R2079: the chat SDK version and its AAR SHA-256 are pinned in app/chat-sdk.lock. -PchatSdkVersion may be omitted;
// when given it must equal the lock. verifyChatSdkLock checks the resolved AAR bytes on every build.
val chatSdkLock: Map<String, String> = file("chat-sdk.lock").takeIf { it.isFile }?.readLines()
    ?.filter { it.isNotBlank() && !it.trimStart().startsWith("#") && it.contains("=") }
    ?.associate { it.substringBefore("=").trim() to it.substringAfter("=").trim() }
    ?: throw GradleException("app/chat-sdk.lock missing: the chat SDK must be pinned (PM R2079).")
val chatSdkLockedVersion: String = chatSdkLock["chat_sdk_version"]?.takeIf { it.isNotBlank() }
    ?: throw GradleException("app/chat-sdk.lock has no chat_sdk_version")
val chatSdkLockedSha: String = chatSdkLock["chat_sdk_aar_sha256"]?.lowercase()?.takeIf { Regex("^[0-9a-f]{64}$").matches(it) }
    ?: throw GradleException("app/chat-sdk.lock has no valid chat_sdk_aar_sha256")
val chatSdkLockedQa = chatSdkLock["chat_sdk_qa"] == "true"
val chatSdkVersion: String = providers.gradleProperty("chatSdkVersion").orNull?.also {
    if (it != chatSdkLockedVersion) throw GradleException("-PchatSdkVersion=$it is not the pinned $chatSdkLockedVersion in app/chat-sdk.lock (update the lock in its own reviewed commit).")
} ?: chatSdkLockedVersion
// QA write guard (PM / PWA integration 2026-11-14): -PqaWriteGuard=true turns it on in debug builds only.
// Release and store builds always get false.
val qaWriteGuard = providers.gradleProperty("qaWriteGuard").orNull == "true"
// Plan N page record + legacy PGP migration (spec r3ay 25.52D). PM R675 (2026-11-14, spec r3cx §25.52AZ.4): the
// window.BeamioShellRecord channel is part of release and store builds. Debug builds have it too unless -PplanN=false.
val planN = providers.gradleProperty("planN").orNull != "false"
// PM R766/R771/R789/R826: the sensitive CashTreesAndroid methods live on window.BeamioShell / window.BeamioChat
// (spec §25.52AA.11). CashTreesJsBridgeLegacy re-exposes them on CashTreesAndroid for pages that have not switched.
// Defaults (R826 d): debug true (QA transition); release false; store always false (no override). A release built with
// -PlegacySensitiveBridge=true is a QA artifact (t168r legacy probe), never a release package (DR.3, R788).
val legacySensitiveBridgeProp = providers.gradleProperty("legacySensitiveBridge").orNull
val legacyDebug = legacySensitiveBridgeProp != "false"
val legacyRelease = legacySensitiveBridgeProp == "true"
// QA native evidence page (PM R591, §25.37.4 A5): -PchatQaHooks compiles src/qaHooks into debug builds only and swaps in
// src/qaHooksDebug/AndroidManifest.xml. Release and store never get it; scripts/verify-android-no-qa-hooks.sh checks the APKs.
val chatQaHooks = providers.gradleProperty("chatQaHooks").isPresent
if (chatQaHooks && !chatSdkNativeKey) throw GradleException("-PchatQaHooks needs the native-key SDK line (-PchatSdkNativeKey=true).")
// QA only (R551): debug builds use release-like cleartext rules so the chat SDK can reach node IPs over HTTP.
val qaCleartextNsc = providers.gradleProperty("qaCleartextNsc").orNull == "true"
// AH.6 item 3 (PM R639/R642, spec r3ck §25.52AM.2): -PqaReleaseVariant=true builds the release type unchanged except for
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
// PM R2042: bits from a QA candidate manifest are QA only. The store build type takes capability bits only from a freeze
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
        applicationId = if (qaReleaseVariant) "com.beamio.app.t168r" else "com.beamio.app.t168" // QA ONLY: never the store id
        minSdk = 24
        targetSdk = 36
        versionCode = 169
        versionName = "1.0.163"

        // t168r (AH.6 item 3): a plain framework Instrumentation, since the minified release app lacks androidx.tracing.
        testInstrumentationRunner = if (qaReleaseVariant) "com.beamio.app.ah6.Ah6BridgeInstrumentation" else "androidx.test.runner.AndroidJUnitRunner"

        // SHA-256 of the bundled SilentPassUI.zip; the store bootstrap refuses to load anything else.
        // With -PpwaFreezeManifest the preBuild gate already requires this file to equal the frozen zip_sha256.
        buildConfigField("String", "PWA_ZIP_SHA256", "\"$embeddedPwaZipSha256\"")
        // §25.52Y.38 item 2 (a): capability bits of that same package and the zip_sha256 they are bound to ("" when none).
        buildConfigField("String", "PWA_CAPABILITIES", "\"${pwaCapabilities.joinToString(",")}\"")
        buildConfigField("String", "PWA_CAPABILITIES_ZIP_SHA256", "\"${if (pwaCapabilities.isEmpty()) "" else embeddedPwaZipSha256}\"")
    }
    buildFeatures {
        buildConfig = true
    }
    // Every build type carries the label; only debugqa sets it (HD.2: products are marked QA).
    defaultConfig.buildConfigField("String", "QA_BUILD_LABEL", "\"\"")
    packaging {
        // bcprov, bcutil and bcpg each ship META-INF/LICENSE.md (same BC MIT text); keep one copy.
        resources { pickFirsts += setOf("META-INF/LICENSE.md") }
    }
    sourceSets {
        // Remote PWA update code (manifest, download, staging) only in non-store build types.
        getByName("debug").let { it.java.directories.add("src/ota/java"); it.kotlin.directories.add("src/ota/java") }
        getByName("release").let { it.java.directories.add("src/ota/java"); it.kotlin.directories.add("src/ota/java") }
        maybeCreate("store").let { it.java.directories.add("src/noota/java"); it.kotlin.directories.add("src/noota/java") }
        // PM R675: the QA write guard lives in src/debug; release and store get a no-op stub with the same calls.
        getByName("release").let { it.java.directories.add("src/qaGuardStub/java"); it.kotlin.directories.add("src/qaGuardStub/java") }
        maybeCreate("store").let { it.java.directories.add("src/qaGuardStub/java"); it.kotlin.directories.add("src/qaGuardStub/java") }
        getByName("debug").res.directories.add(if (qaCleartextNsc) "src/qaCleartextNsc/res" else if (otaLocalStub) "src/otaLocalStub/res" else "src/otaDefaultNsc/res")
        if (chatQaHooks) getByName("debug").let {
            it.java.directories.add("src/qaHooks/java"); it.kotlin.directories.add("src/qaHooks/java")
            it.manifest.srcFile("src/qaHooksDebug/AndroidManifest.xml")
        }
        // Spec §25.52HD (HD.1, PM R2088): debugqa is the debug build under the approved name; same QA code and manifest as debug.
        maybeCreate("debugqa").let {
            for (d in listOf("src/debug/java", "src/ota/java")) { it.java.directories.add(d); it.kotlin.directories.add(d) }
            it.manifest.srcFile("src/debug/AndroidManifest.xml")
            it.res.directories.add(if (qaCleartextNsc) "src/qaCleartextNsc/res" else "src/otaDefaultNsc/res")
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
            buildConfigField("boolean", "LEGACY_SENSITIVE_BRIDGE", legacyDebug.toString()) // R826 d: debug/QA may keep it
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
            buildConfigField("boolean", "PLAN_N", "true") // PM R675: plan N channel in release/store
            buildConfigField("boolean", "LEGACY_SENSITIVE_BRIDGE", legacyRelease.toString()) // R826 d: default false
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
            if (qaReleaseVariant) {
                signingConfig = signingConfigs.getByName("debug")
            } else if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        // Spec §25.52HD.1/HD.2 (owner's written approval R1249, PM R2088): the internal QA build named `debugqa`, only for the
        // Samsung S25, application id com.beamio.app.t168 (forced below), debug key only (never the store certificate), with the
        // QA chat SDK of app/chat-sdk.lock and the QA manifest's capability bits. It declares nothing by itself: per HD.3 a
        // capability such as the native-keys bit comes only from the SDK build. Not for release, store or anyone outside.
        create("debugqa") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            isDebuggable = true
            versionNameSuffix = "-debugqa"
            signingConfig = signingConfigs.getByName("debug")
            buildConfigField("String", "QA_BUILD_LABEL", "\"debugqa\"")
        }
        create("store") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            buildConfigField("boolean", "REMOTE_PWA_UPDATE", "false")
            buildConfigField("boolean", "QA_WRITE_GUARD", "false")
            buildConfigField("boolean", "PLAN_N", "true") // PM R675: plan N channel in release/store
            buildConfigField("boolean", "LEGACY_SENSITIVE_BRIDGE", "false") // R826 d: store never re-exposes them
            // initWith copied the OTA fields from release: blank them so no update URL reaches store.
            buildConfigField("String", "OTA_MANIFEST_URL", "\"\"")
            buildConfigField("String", "OTA_BUNDLE_BASE", "\"\"")
            buildConfigField("long", "OTA_CHECK_INTERVAL_MS", "0L")
            // PM R2042: QA-manifest capability bits never reach a store build.
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

/**
 * PWA version gate (owner rule 2026-11-11): the shell must embed the latest
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
 *   QA candidate (NOT FROZEN, PM R509): -PpwaUnreleasedTest=true -PpwaQaManifest=<qa manifest JSON>
 *                            (status "qa-candidate", not_frozen true, freeze_kind "qa-candidate-not-frozen"; the
 *                            embedded ZIP sha256 and version must equal its zip_sha256 and version). Verdict QA only.
 */
val pwaUnreleasedTest = providers.gradleProperty("pwaUnreleasedTest").orNull == "true"
val pwaFreezeManifest = providers.gradleProperty("pwaFreezeManifest").orNull
val pwaQaManifest = providers.gradleProperty("pwaQaManifest").orNull
if (pwaUnreleasedTest) {
    android.defaultConfig.versionNameSuffix = "-pwa-unreleased-test"
}
val verifyShellPwaVersion by tasks.registering(Exec::class) {
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
        commandLine(args)
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
 * PM R2079: the resolved chat SDK AAR must have the SHA-256 pinned in app/chat-sdk.lock. Runs before every build; there is
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
 * Spec §25.52HD (PM R2088): debugqa is the approved S25 QA build only. It cannot be combined with the release-QA probe
 * variant (whose id is t168r), and a debugqa product must not reach a release or store artifact.
 */
if (qaReleaseVariant && gradle.startParameter.taskNames.any { it.contains("debugqa", ignoreCase = true) }) {
    throw GradleException("debugqa is com.beamio.app.t168 only; -PqaReleaseVariant (t168r) cannot build it.")
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
    onVariants(selector().withBuildType("debugqa")) { variant -> variant.applicationId.set("com.beamio.app.t168") }
    // PM R677: release also gets host unit tests (src/testRelease checks the release build shape).
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
    // Version pinned in app/chat-sdk.lock (PM R2079); the local maven dir comes from -PchatSdkLocalRepo (settings.gradle.kts).
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

// QA hooks must never reach a release or store artifact (PM R591): refuse the combination outright.
gradle.taskGraph.whenReady {
    if (chatQaHooks && allTasks.any { t -> t.project == project && Regex("(?i)(assemble|bundle|package)(release|store)").containsMatchIn(t.name) }) {
        throw GradleException("-PchatQaHooks is for debug QA builds only; release/store packaging refused.")
    }
}
