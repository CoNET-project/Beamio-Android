package com.beamio.app.qa.readfault

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Switch for the QA read-fault path. Exported but protected by android.permission.DUMP in the manifest, which only the shell
 * (adb) and system hold, so no third-party app can send it. Extra "enabled" (boolean) turns the fault on or off.
 */
class QaReadFaultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        QaReadFaultImpl.setEnabled(intent.getBooleanExtra("enabled", false))
    }

    companion object {
        const val ACTION = "com.beamio.app.qa.READ_FAULT"
    }
}
