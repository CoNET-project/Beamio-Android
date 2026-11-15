package com.beamio.app.nativekey

/**
 * The shell's view of the native wallet key (spec 25.25, 25.26.4c). The SDK binding in `src/nativekeySdk` provides
 * the real one; the default build (chat SDK 0.2.6, `src/nativekeyNone`) has no native key and uses [Unavailable].
 *
 * Key text passes through [importPrivateKey] and [importMnemonic] only. Nothing here keeps, logs or returns it.
 */
interface NativeKeyBackend {
    /** `false`: the device has no native key record (G0). `true`: a record exists. `null`: not known (no SDK support). */
    fun hasKey(): Boolean?

    /** `true` once the SDK session is initialised (G2, spec §25.26.4c); `null` when not known. */
    fun sessionReady(): Boolean? = null

    fun importPrivateKey(raw: String): ImportCode

    fun importMnemonic(raw: String): ImportCode

    object Unavailable : NativeKeyBackend {
        override fun hasKey(): Boolean? = null
        override fun importPrivateKey(raw: String) = ImportCode.NOT_SUPPORTED
        override fun importMnemonic(raw: String) = ImportCode.NOT_SUPPORTED
    }
}

/** Import result codes (spec 25.25.5, 25.26.3). [NOT_SUPPORTED] is the shell's own: no SDK support in this build (0.2.6). The page still opens; a submit
 * answers `not_supported` with its message and never reports success. */
enum class ImportCode(val wire: String) {
    OK("ok"),
    INVALID_FORMAT("invalid_format"),
    INVALID_KEY("invalid_key"),
    INVALID_MNEMONIC("invalid_mnemonic"),
    ADDRESS_MISMATCH("address_mismatch"),
    ALREADY_EXISTS("already_exists"),
    WRITE_FAILED("write_failed"),
    READBACK_FAILED("readback_failed"),
    CANCELLED("cancelled"),
    NOT_SUPPORTED("not_supported"),
    ;

    companion object {
        /** Maps an SDK result code. An unknown code is treated as a failed write (nothing is assumed imported). */
        fun fromWire(wire: String): ImportCode = entries.firstOrNull { it.wire == wire } ?: WRITE_FAILED
    }
}

/** The backend in use. Set once by `NativeKeySdkBinding.install`. */
object NativeKeyBackends {
    @Volatile
    var current: NativeKeyBackend = NativeKeyBackend.Unavailable
}
