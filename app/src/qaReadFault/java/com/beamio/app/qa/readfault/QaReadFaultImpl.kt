package com.beamio.app.qa.readfault

import com.beamio.app.legacy.QaReadFault
import com.beamio.app.legacy.QaReadFaults
import com.beamio.app.legacy.ShellRecordReplies

/**
 * QA-only read failure (QA exception, kept in an independent source set). Compiled only into the t168 read-fault debugqa
 * package (-PchatQaHooks with -PallowQaHooksOnDebugqa=t168-read-fault). Off by default and reset on process restart. When on,
 * shellRecordRead is answered with the shell's own read-failure reply (ShellRecordReplies.fallback). No keystore, record or SDK access.
 */
internal object QaReadFaultImpl : QaReadFault {
    @Volatile
    private var enabled = false

    override fun replyFor(type: String, data: String): String? =
        if (enabled && type == "shellRecordRead") ShellRecordReplies.fallback(data) else null

    fun setEnabled(on: Boolean) {
        enabled = on
        QaReadFaults.current = if (on) this else null
    }
}
