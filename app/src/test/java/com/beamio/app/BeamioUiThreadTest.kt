package com.beamio.app

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class BeamioUiThreadTest {
    private val posted = mutableListOf<Runnable>()
    private var onMain = false
    private lateinit var savedIsMain: () -> Boolean
    private lateinit var savedPost: (Runnable) -> Unit

    @Before
    fun fakeLooper() {
        savedIsMain = BeamioUiThread.isMainThread
        savedPost = BeamioUiThread.postToMain
        BeamioUiThread.isMainThread = { onMain }
        BeamioUiThread.postToMain = { posted.add(it) }
    }

    @After
    fun restore() {
        BeamioUiThread.isMainThread = savedIsMain
        BeamioUiThread.postToMain = savedPost
    }

    @Test
    fun backgroundCallerIsPostedNotRunInline() {
        // FCM thread: the window update must not run here (CalledFromWrongThreadException).
        onMain = false
        var ran = 0
        BeamioUiThread.run { ran++ }
        assertEquals(0, ran)
        assertEquals(1, posted.size)
        posted.single().run()
        assertEquals(1, ran)
    }

    @Test
    fun mainThreadCallerRunsAtOnce() {
        onMain = true
        var ran = 0
        BeamioUiThread.run { ran++ }
        assertEquals(1, ran)
        assertEquals(0, posted.size)
    }
}
