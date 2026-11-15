package com.beamio.app.nativekey

import android.app.Activity
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.beamio.app.R
import java.util.concurrent.Executors

/**
 * Native recovery page (QA shell). The recovery code is typed only here: masked field with the same secure settings as
 * the import page (no suggestions or learning, no autofill, no saved state, no copy or cut, accessibility-data-sensitive
 * on Android 14+), FLAG_SECURE window. On submit the text is read into a char array, the field is cleared, the array is
 * wiped after the backend call. Only the result code (and the public address on success) goes to the web page.
 */
class NativeRecoveryActivity : AppCompatActivity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var busy = false
    private var succeeded = false

    private lateinit var field: EditText
    private lateinit var accountField: EditText
    private lateinit var passwordField: EditText
    private lateinit var status: TextView
    private lateinit var button: TextView
    private lateinit var codeTab: TextView
    private lateinit var passwordTab: TextView
    private var pathB = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        setContentView(buildContent())
        applyPath(false)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = cancel()
        })
    }

    override fun onStop() {
        super.onStop()
        if (::field.isInitialized) field.text.clear()
        if (::passwordField.isInitialized) passwordField.text.clear()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        if (!succeeded) NativeRecoveryBackends.current.cancel()
        super.onDestroy()
    }

    private fun submit() {
        if (busy) return
        busy = true
        button.isEnabled = false
        button.alpha = 0.6f
        status.visibility = View.GONE
        if (pathB) {
            val account = accountField.text.toString()
            val e = passwordField.text
            val pw = CharArray(e.length).also { e.getChars(0, e.length, it, 0) }
            e.clear()
            worker.execute {
                val outcome = NativeRecoveryFlow.submitPassword(account, pw)
                main.post { showResult(outcome) }
            }
        } else {
            val editable = field.text
            val code = CharArray(editable.length).also { editable.getChars(0, editable.length, it, 0) }
            editable.clear()
            worker.execute {
                val outcome = NativeRecoveryFlow.submit(code)
                main.post { showResult(outcome) }
            }
        }
    }

    /** First screen choice (r3u 25.42.3 item 1): recovery code (A) or account name and password (B). */
    private fun applyPath(b: Boolean) {
        pathB = b
        field.text.clear()
        passwordField.text.clear()
        status.visibility = View.GONE
        field.visibility = if (b) View.GONE else View.VISIBLE
        accountField.visibility = if (b) View.VISIBLE else View.GONE
        passwordField.visibility = if (b) View.VISIBLE else View.GONE
        styleTab(codeTab, !b)
        styleTab(passwordTab, b)
    }

    private fun styleTab(tab: TextView, selected: Boolean) {
        tab.setTextColor(if (selected) BG else WHITE_75)
        tab.isSelected = selected
        tab.background = if (selected) GradientDrawable().apply {
            setColor(Color.WHITE)
            cornerRadius = dp(999).toFloat()
        } else null
    }

    private fun showResult(o: RecoveryOutcome) {
        if (isFinishing || isDestroyed) return
        busy = false
        status.setText(messageRes(o.code))
        status.setTextColor(if (o.code == RecoveryCode.OK) Color.WHITE else AMBER_200)
        status.visibility = View.VISIBLE
        status.announceForAccessibility(status.text)
        if (o.code == RecoveryCode.OK || o.code == RecoveryCode.ALREADY_EXISTS) {
            // The SDK has already sent nativeRecoveryResult to the web page.
            succeeded = true
            main.postDelayed({
                setResult(Activity.RESULT_OK)
                finish()
            }, 800L)
        } else {
            // Failures stay on the page so the code can be typed again (spec r3u 25.42.4 item 5).
            button.isEnabled = true
            button.alpha = 1f
        }
    }

    private fun cancel() {
        field.text.clear()
        passwordField.text.clear()
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    private fun buildContent(): View {
        val root = ScrollView(this).apply {
            setBackgroundColor(BG)
            isFillViewport = true
        }
        val frame = FrameLayout(this).apply { setPadding(dp(24), dp(16), dp(24), dp(16)) }
        root.addView(frame, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = GradientDrawable().apply {
                setColor(0x1AFFFFFF)
                setStroke(dp(1), 0x26FFFFFF)
                cornerRadius = dp(24).toFloat()
            }
        }
        frame.addView(card, FrameLayout.LayoutParams(
            minOf(resources.displayMetrics.widthPixels - dp(48), dp(448)), ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER,
        ))
        card.addView(text(R.string.native_recovery_title, 20f, Color.WHITE, bold = true).apply {
            isFocusable = true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
        }, fullWidth())
        card.addView(text(R.string.native_recovery_body, 14f, WHITE_75).apply { setLineSpacing(0f, 1.3f) }, fullWidth(top = 12))
        field = EditText(this).apply {
            setTextColor(BG)
            setHintTextColor(Color.GRAY)
            textSize = 15f
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(12).toFloat()
            }
            setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_DONE) { submit(); true } else false
            }
        }
        NativeKeyImportActivity.configureSecureInput(field, ImportMode.PRIVATE_KEY)
        field.setHint(R.string.native_recovery_hint)
        val tabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = GradientDrawable().apply {
                setColor(0x1AFFFFFF)
                cornerRadius = dp(999).toFloat()
            }
            setPadding(dp(4), dp(4), dp(4), dp(4))
        }
        codeTab = tabView(R.string.native_recovery_tab_code) { applyPath(false) }
        passwordTab = tabView(R.string.native_recovery_tab_password) { applyPath(true) }
        tabs.addView(codeTab, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        tabs.addView(passwordTab, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        card.addView(tabs, fullWidth(top = 16))
        card.addView(field, fullWidth(top = 12))
        // Path B: account name is ordinary text (no case or @ rewriting); the password is a secure field.
        accountField = plainField().apply {
            setHint(R.string.native_recovery_hint_account)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            isSaveEnabled = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        card.addView(accountField, fullWidth(top = 12))
        passwordField = plainField()
        NativeKeyImportActivity.configureSecureInput(passwordField, ImportMode.PRIVATE_KEY)
        passwordField.setHint(R.string.native_recovery_hint_password)
        card.addView(passwordField, fullWidth(top = 12))
        status = text(0, 14f, AMBER_200).apply {
            visibility = View.GONE
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        card.addView(status, fullWidth(top = 12))
        button = text(R.string.native_recovery_button, 14f, BG, bold = true).apply {
            setPadding(dp(20), dp(10), dp(20), dp(10))
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(999).toFloat()
            }
            isClickable = true
            isFocusable = true
            setOnClickListener { submit() }
        }
        card.addView(button, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(20) })
        val cancel = text(R.string.native_key_import_cancel, 14f, WHITE_75).apply {
            paintFlags = paintFlags or Paint.UNDERLINE_TEXT_FLAG
            setPadding(dp(8), dp(8), dp(8), dp(8))
            isClickable = true
            isFocusable = true
            setOnClickListener { cancel() }
        }
        card.addView(cancel, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(4) })
        return root
    }

    private fun plainField() = EditText(this).apply {
        setTextColor(BG)
        setHintTextColor(Color.GRAY)
        textSize = 15f
        setPadding(dp(14), dp(12), dp(14), dp(12))
        background = GradientDrawable().apply {
            setColor(Color.WHITE)
            cornerRadius = dp(12).toFloat()
        }
        maxLines = 1
        setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) { submit(); true } else false
        }
    }

    private fun tabView(res: Int, onClick: () -> Unit) = text(res, 13f, WHITE_75).apply {
        setPadding(dp(8), dp(8), dp(8), dp(8))
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
    }

    private fun text(res: Int, sp: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
        if (res != 0) setText(res)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(color)
        gravity = Gravity.CENTER
        if (bold) typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }

    private fun fullWidth(top: Int = 0) =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(top) }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    companion object {
        private const val BG = 0xFF071126.toInt()
        private const val WHITE_75 = 0xBFFFFFFF.toInt()
        private const val AMBER_200 = 0xFFFDE68A.toInt()

        fun messageRes(code: RecoveryCode): Int = when (code) {
            RecoveryCode.OK, RecoveryCode.ALREADY_EXISTS -> R.string.native_recovery_ok
            RecoveryCode.INVALID_FORMAT -> R.string.native_recovery_err_format
            RecoveryCode.NOT_FOUND -> R.string.native_recovery_err_not_found
            RecoveryCode.NETWORK_ERROR -> R.string.native_recovery_err_network
            RecoveryCode.BACKOFF -> R.string.native_recovery_err_backoff
            RecoveryCode.BAD_PIN -> R.string.native_recovery_err_bad_password
            RecoveryCode.LEGACY_RECORD -> R.string.native_recovery_err_legacy
            else -> R.string.native_recovery_err_other
        }
    }
}
