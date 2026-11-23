package com.beamio.app

/**
 * Log hygiene (defence in depth): what release and store builds let reach logcat.
 * Callers pass BuildConfig.DEBUG, so both rules are plain functions a JVM test can check for either build.
 */
object ReleaseLogPolicy {
    /**
     * WebChromeClient.onConsoleMessage return value. true consumes the message, so the WebView's default handler does not
     * write page console text to logcat; release and store always consume. DEBUG builds (debug, debugqa) keep the default.
     */
    fun consumeConsoleMessage(debug: Boolean): Boolean = !debug

    /**
     * Text for an exception in a log line. An org.json syntax error copies its input into the message, so release and store
     * log the exception class only; DEBUG builds keep the message.
     */
    fun exceptionDetail(error: Throwable, debug: Boolean): String =
        if (debug) error.message ?: error.javaClass.simpleName else error.javaClass.simpleName
}
