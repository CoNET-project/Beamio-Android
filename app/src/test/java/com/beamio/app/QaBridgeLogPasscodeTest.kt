package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Test

/** Frozen passcode protocol v1 (shell side): `passcode_required` is a printable not-ready reason; anything else stays `<unknown>`. */
class QaBridgeLogPasscodeTest {
    @Test fun passcodeRequiredIsPrinted() {
        assertEquals("passcode_required", QaBridgeLogFields.value("notReadyReason", "passcode_required"))
    }

    @Test fun unknownReasonIsStillHidden() {
        assertEquals(QaBridgeLogFields.UNKNOWN, QaBridgeLogFields.value("notReadyReason", "123456"))
    }
}
