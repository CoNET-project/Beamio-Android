package com.beamio.app

/**
 * The same incoming call is often reported twice: the page's mailbox listen
 * reports it, then the FCM push for it lands (Samsung 1.0.161: 0.3 s apart,
 * about 4 s after locking). Only the first report submits to Telecom.
 */
internal object BeamioIncomingRepeatReport {
    /**
     * A repeat refreshes the caller on the shown window only once Telecom has
     * the call's Connection or a window / CallStyle is up. Before that the
     * window is still being opened from Telecom's callback (which reads the
     * caller the repeat just stored); opening it from the repeat as well would
     * present it twice.
     */
    fun refreshShownWindow(hasConnection: Boolean, windowArmed: Boolean): Boolean =
        hasConnection || windowArmed
}
