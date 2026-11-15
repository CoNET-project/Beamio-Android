package com.beamio.app

/**
 * In-call tools panel over peer video: a tap on the open panel outside its
 * buttons collapses it, the same as the grabber. Same rule on iOS and in the PWA.
 */
object InCallToolsPanelTap {
    fun collapses(peerVideoActive: Boolean, toolsExpanded: Boolean): Boolean =
        peerVideoActive && toolsExpanded
}
