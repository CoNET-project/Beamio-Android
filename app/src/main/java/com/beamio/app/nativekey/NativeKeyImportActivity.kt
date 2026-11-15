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
import android.text.InputType
import android.util.TypedValue
import android.view.ActionMode
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.beamio.app.R
import java.util.concurrent.Executors

/**
 * The native wallet import page (spec 25.25.1, 25.26.3), laid out like the PWA locked page NativeKeyImportRequired:
 * dark background, one card with a lock, title, body, an alert line for failures, a white pill button and a text button.
 *
 * - The key or phrase is typed only here, in a masked password field (both modes): no suggestions, no personalised
 *   learning, no autofill, no saved state, copy and cut removed, accessibility-data-sensitive on Android 14+, and the
 *   window is FLAG_SECURE (no screenshots or recents preview). A pasted value is cleared from the clipboard on submit.
 * - On submit the field is cleared before the import runs. The text is never logged, shown or sent to the WebView.
 * - Results show inline. After `ok` (or `already_exists`) the page closes with RESULT_OK and MainActivity reloads the
 *   web page, which then checks the key state again. Cancel and Back close with no message (`cancelled`).
 */
class NativeKeyImportActivity : AppCompatActivity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private var mode = ImportMode.PRIVATE_KEY
    private var busy = false

    private lateinit var field: EditText
    private lateinit var status: TextView
    private lateinit var importButton: TextView
    private lateinit var keyTab: TextView
    private lateinit var mnemonicTab: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        setContentView(buildContent())
        applyMode(ImportMode.PRIVATE_KEY)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = cancel()
        })
    }

    override fun onStop() {
        super.onStop()
        // Leaving the page (home, app switcher) drops whatever was typed.
        if (::field.isInitialized) field.text.clear()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun submit() {
        if (busy) return
        val raw = field.text.toString()
        field.text.clear()
        clearClipboardIfItHolds(raw)
        busy = true
        importButton.isEnabled = false
        importButton.alpha = 0.6f
        val m = mode
        worker.execute {
            val code = NativeKeyImportFlow.submit(m, raw)
            main.post { showResult(code) }
        }
    }

    private fun showResult(code: ImportCode) {
        if (isFinishing || isDestroyed) return
        busy = false
        val msg = NativeKeyImportFlow.messageRes(code)
        if (msg != null) {
            status.setText(msg)
            status.setTextColor(if (code == ImportCode.OK) Color.WHITE else AMBER_200)
            status.visibility = View.VISIBLE
            status.announceForAccessibility(status.text)
        }
        if (NativeKeyImportFlow.closesAndReloads(code)) {
            main.postDelayed({
                setResult(Activity.RESULT_OK)
                finish()
            }, NativeKeyImportFlow.closeDelayMs(code))
        } else {
            importButton.isEnabled = true
            importButton.alpha = 1f
        }
    }

    /** A pasted key or phrase must not stay on the clipboard after the import. */
    private fun clearClipboardIfItHolds(submitted: String) {
        runCatching {
            val cm = getSystemService(android.content.ClipboardManager::class.java) ?: return
            val clip = cm.primaryClip ?: return
            val text = if (clip.itemCount > 0) clip.getItemAt(0).coerceToText(this) else null
            if (!shouldClearClipboard(text, submitted)) return
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
            else cm.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
        }
    }

    private fun cancel() {
        field.text.clear()
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    private fun applyMode(next: ImportMode) {
        mode = next
        field.text.clear()
        status.visibility = View.GONE
        configureSecureInput(field, next)
        field.setHint(if (next == ImportMode.PRIVATE_KEY) R.string.native_key_import_hint_key else R.string.native_key_import_hint_mnemonic)
        styleTab(keyTab, next == ImportMode.PRIVATE_KEY)
        styleTab(mnemonicTab, next == ImportMode.MNEMONIC)
    }

    // --- layout -------------------------------------------------------------------------------------------------

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
            minOf(resources.displayMetrics.widthPixels - dp(48), dp(448)),
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER,
        ))

        val lockBg = FrameLayout(this).apply {
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(0x26FFFFFF)
            }
        }
        lockBg.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_native_key_lock)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, FrameLayout.LayoutParams(dp(24), dp(24), Gravity.CENTER))
        card.addView(lockBg, LinearLayout.LayoutParams(dp(48), dp(48)).apply { bottomMargin = dp(16) })

        card.addView(text(R.string.native_key_import_title, 20f, Color.WHITE, bold = true).apply {
            isFocusable = true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
        }, fullWidth())
        card.addView(text(R.string.native_key_import_body, 14f, WHITE_75).apply {
            setLineSpacing(0f, 1.3f)
        }, fullWidth(top = 12))

        val tabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = GradientDrawable().apply {
                setColor(0x1AFFFFFF)
                cornerRadius = dp(999).toFloat()
            }
            setPadding(dp(4), dp(4), dp(4), dp(4))
        }
        keyTab = tab(R.string.native_key_import_mode_key) { applyMode(ImportMode.PRIVATE_KEY) }
        mnemonicTab = tab(R.string.native_key_import_mode_mnemonic) { applyMode(ImportMode.MNEMONIC) }
        tabs.addView(keyTab, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        tabs.addView(mnemonicTab, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        card.addView(tabs, fullWidth(top = 16))

        field = EditText(this).apply {
            setTextColor(BG)
            setHintTextColor(Color.GRAY)
            textSize = 15f
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(12).toFloat()
            }
            contentDescription = null
            setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_DONE) { submit(); true } else false
            }
        }
        card.addView(field, fullWidth(top = 12))

        status = text(0, 14f, AMBER_200).apply {
            visibility = View.GONE
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        card.addView(status, fullWidth(top = 12))

        importButton = text(R.string.native_key_import_button, 14f, BG, bold = true).apply {
            setPadding(dp(20), dp(10), dp(20), dp(10))
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(999).toFloat()
            }
            isClickable = true
            isFocusable = true
            setOnClickListener { submit() }
        }
        card.addView(importButton, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(20) })

        val cancel = text(R.string.native_key_import_cancel, 14f, WHITE_75).apply {
            paintFlags = paintFlags or Paint.UNDERLINE_TEXT_FLAG
            setPadding(dp(8), dp(8), dp(8), dp(8))
            isClickable = true
            isFocusable = true
            setOnClickListener { cancel() }
        }
        card.addView(cancel, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(4) })
        return root
    }

    private fun text(res: Int, sp: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
        if (res != 0) setText(res)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(color)
        gravity = Gravity.CENTER
        if (bold) typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }

    private fun tab(res: Int, onClick: () -> Unit) = text(res, 13f, WHITE_75).apply {
        setPadding(dp(8), dp(8), dp(8), dp(8))
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
    }

    private fun styleTab(tab: TextView, selected: Boolean) {
        tab.setTextColor(if (selected) BG else WHITE_75)
        tab.isSelected = selected
        tab.background = if (selected) {
            GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(999).toFloat()
            }
        } else {
            null
        }
    }

    private fun fullWidth(top: Int = 0) =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(top)
        }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    companion object {
        private const val BG = 0xFF071126.toInt() // #071126
        private const val WHITE_75 = 0xBFFFFFFF.toInt()
        private const val AMBER_200 = 0xFFFDE68A.toInt() // amber-200

        /**
         * InputType for both modes: a masked password field with no suggestions. The recovery phrase is masked too:
         * a visible field hands its text to accessibility events and nodes (screen readers, logging services).
         */
        @Suppress("UNUSED_PARAMETER")
        fun inputTypeFor(mode: ImportMode): Int =
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS

        /** Clear the clipboard after submit only when it holds exactly the text that was imported (pasted key or phrase). */
        fun shouldClearClipboard(clipText: CharSequence?, submitted: String): Boolean =
            clipText != null && submitted.isNotBlank() && clipText.toString().trim() == submitted.trim()

        const val IME_OPTIONS = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
            EditorInfo.IME_FLAG_NO_EXTRACT_UI

        /** Secure field settings (spec 25.25.2 item 5). */
        fun configureSecureInput(field: EditText, mode: ImportMode) {
            field.inputType = inputTypeFor(mode)
            field.imeOptions = IME_OPTIONS
            field.isSaveEnabled = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                field.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            }
            field.isLongClickable = true // paste stays available
            field.customSelectionActionModeCallback = NoCopyCallback
            field.contentDescription = null
            if (Build.VERSION.SDK_INT >= 34) {
                // Android 14+: only services that declare isAccessibilityTool may read this field.
                field.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
            }
            field.minLines = 1
            field.maxLines = 1
            field.gravity = Gravity.CENTER_VERTICAL or Gravity.START
        }

        /** Removes copy, cut and share from the selection menu so the text cannot leave the field. */
        private object NoCopyCallback : ActionMode.Callback {
            override fun onCreateActionMode(mode: ActionMode, menu: Menu): Boolean = true
            override fun onPrepareActionMode(mode: ActionMode, menu: Menu): Boolean {
                menu.removeItem(android.R.id.copy)
                menu.removeItem(android.R.id.cut)
                menu.removeItem(android.R.id.shareText)
                return true
            }
            override fun onActionItemClicked(mode: ActionMode, item: MenuItem): Boolean = false
            override fun onDestroyActionMode(mode: ActionMode) = Unit
        }
    }
}
