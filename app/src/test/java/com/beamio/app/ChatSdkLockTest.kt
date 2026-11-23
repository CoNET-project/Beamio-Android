package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**: the chat SDK is pinned in app/chat-sdk.lock and the build checks the resolved AAR against it. */
class ChatSdkLockTest {
    private val lock = File("chat-sdk.lock").readLines()
        .filter { it.isNotBlank() && !it.startsWith("#") && it.contains("=") }
        .associate { it.substringBefore("=") to it.substringAfter("=") }

    @Test
    fun lockHasVersionShaAndCommits() {
        assertTrue(lock["chat_sdk_version"]!!.isNotBlank())
        assertTrue(Regex("^[0-9a-f]{64}$").matches(lock["chat_sdk_aar_sha256"]!!))
        assertTrue(Regex("^[0-9a-f]{40}$").matches(lock["chat_sdk_source_commit"]!!))
        assertTrue(Regex("^[0-9a-f]{40}$").matches(lock["chat_sdk_code_commit"]!!))
        assertTrue(lock["chat_sdk_qa"] == "true" || lock["chat_sdk_qa"] == "false")
        // no private path in the lock
        assertFalse(File("chat-sdk.lock").readText().contains("/Users/"))
    }

    @Test
    fun gradleUsesTheLockAndHasNoOldDefault() {
        val g = File("build.gradle.kts").readText()
        assertFalse(g.contains("getOrElse(\"0.2.6\")"))
        assertTrue(g.contains("implementation(\"network.conet:chat:\$chatSdkVersion\")"))
        assertTrue(g.contains("tasks.matching { it.name == \"preBuild\" }.configureEach { dependsOn(verifyChatSdkLock) }"))
        assertTrue(g.contains("if (sha != chatSdkLockedSha)"))
        assertTrue(g.contains("store packaging refused"))
    }

    @Test
    fun theBuiltSdkIsThePinnedOne() {
        // The SDK on the test classpath reports its own version; it must be the locked one.
        assertEquals(lock["chat_sdk_version"], network.conet.chat.BeamioConetChatProtocol.SDK_VERSION)
    }
}
