package com.beamio.app

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** The inbound receive sits in the SDK delivery path, before the page delivery, and takes no stop action in this step. */
class PasscodeStateWiringTest {
    private val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()

    @Test fun observedBeforeFilterAndDelivery() {
        val body = main.substringAfter("private fun sdkDeliver(deliver: (JSONObject) -> Unit)").substringBefore("private val sdkPayloadFilter").let {
            it.take(1200)
        }
        val observe = body.indexOf("PasscodeStateInbound.observe(raw, PasscodeStateInbound.Source.SDK_NATIVE)")
        val filter = body.indexOf("sdkPayloadFilter.filter(raw)")
        assertTrue(observe >= 0 && filter > observe)
    }

    @Test fun noStopCallInTheInboundPath() {
        val body = main.substringAfter("private fun sdkDeliver(deliver: (JSONObject) -> Unit)").take(1200)
        assertTrue(!body.contains("BeamioNativeVoiceChannel.stop") && !body.contains("shouldStopOnLock"))
    }
}
