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
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.beamio.app.R

/**
 * Native account create page (QA shell, spec r3w 25.46). One confirm button, no input fields, FLAG_SECURE window.
 * The SDK creates and stores the key and tells the web page the result; this page shows only the code's message.
 * `ok` closes the page; other codes keep it open for a retry. Closing calls the SDK's `pageClosed()`.
 */
class NativeAccountCreateActivity : AppCompatActivity() {
    private val main = Handler(Looper.getMainLooper())
    private var busy = false

    private lateinit var status: TextView
    private lateinit var button: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(buildContent())
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = cancel()
        })
    }

    override fun onDestroy() {
        // With no result yet the SDK sends `cancelled`; after a result it sends nothing more.
        NativeAccountCreateBackends.current.pageClosed()
        super.onDestroy()
    }

    private fun confirm() {
        if (busy) return
        busy = true
        button.isEnabled = false
        button.alpha = 0.6f
        status.setText(R.string.native_create_working)
        status.setTextColor(WHITE_75)
        status.visibility = View.VISIBLE
        NativeAccountCreateBackends.current.confirm { code -> main.post { showResult(code) } }
    }

    private fun showResult(code: CreateCode) {
        if (isFinishing || isDestroyed) return
        busy = false
        status.setText(messageRes(code))
        status.setTextColor(if (code == CreateCode.OK) Color.WHITE else AMBER_200)
        status.visibility = View.VISIBLE
        status.announceForAccessibility(status.text)
        if (code == CreateCode.OK) {
            main.postDelayed({
                setResult(Activity.RESULT_OK)
                finish()
            }, 800L)
        } else {
            button.isEnabled = true
            button.alpha = 1f
        }
    }

    private fun cancel() {
        if (busy) return // the create is running; its result closes or re-enables the page
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
        card.addView(text(R.string.native_create_title, 20f, Color.WHITE, bold = true).apply {
            isFocusable = true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) isAccessibilityHeading = true
        }, fullWidth())
        card.addView(text(R.string.native_create_body, 14f, WHITE_75).apply { setLineSpacing(0f, 1.3f) }, fullWidth(top = 12))
        status = text(0, 14f, AMBER_200).apply {
            visibility = View.GONE
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        card.addView(status, fullWidth(top = 12))
        button = text(R.string.native_create_button, 14f, BG, bold = true).apply {
            setPadding(dp(20), dp(10), dp(20), dp(10))
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = dp(999).toFloat()
            }
            isClickable = true
            isFocusable = true
            setOnClickListener { confirm() }
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

        fun messageRes(code: CreateCode): Int = when (code) {
            CreateCode.OK -> R.string.native_create_ok
            CreateCode.ALREADY_EXISTS -> R.string.native_create_err_exists
            CreateCode.CANCELLED -> R.string.native_create_err_other
            CreateCode.WRITE_FAILED, CreateCode.READBACK_FAILED -> R.string.native_create_err_save
        }
    }
}
