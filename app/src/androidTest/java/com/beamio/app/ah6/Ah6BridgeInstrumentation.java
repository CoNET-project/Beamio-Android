package com.beamio.app.ah6;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * AH.6 item 3, rejection path (spec r3ck §25.52AM.2), for the t168r release variant only (-PqaReleaseVariant).
 *
 * Plain framework Instrumentation in Java: the release app under test is minified, so androidx.test (which needs
 * androidx.tracing) and Kotlin library calls cannot be relied on. This class only starts MainActivity and calls the page's
 * production bridge window.CashTreesAndroid.chatModuleCommand from page context; it does not change the app under test.
 * Each answer is logged verbatim under tag BeamioAh6 and returned in the instrumentation result.
 *
 * Run: am instrument -w com.beamio.app.t168r.test/com.beamio.app.ah6.Ah6BridgeInstrumentation
 */
public class Ah6BridgeInstrumentation extends Instrumentation {
    private static final String TAG = "BeamioAh6";
    private static final String[] NAMES = {"r3ckUnknownProbe", "runCommand", "dropEoaKey", "qaRunCommand"};
    private static final int BASE = 990000001;
    private static final String[] SR_CHAT = {"shellRecordRead", "shellRecordWrite", "shellRecordZzUnknown"};

    /** -e legacy false: the build was made with -PlegacySensitiveBridge=false (sensitive methods off CashTreesAndroid). */
    private boolean legacyExpected = true;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        if (arguments != null && "false".equals(arguments.getString("legacy"))) legacyExpected = false;
        start();
    }

    private static WebView find(View v) {
        if (v instanceof WebView) return (WebView) v;
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                WebView w = find(g.getChildAt(i));
                if (w != null) return w;
            }
        }
        return null;
    }

    private String eval(final Activity a, final String js) {
        final String[] out = {"null"};
        final CountDownLatch done = new CountDownLatch(1);
        runOnMainSync(new Runnable() {
            @Override
            public void run() {
                WebView w = find(a.getWindow().getDecorView());
                if (w == null) { out[0] = "\"no_webview\""; done.countDown(); return; }
                w.evaluateJavascript(js, new android.webkit.ValueCallback<String>() {
                    @Override
                    public void onReceiveValue(String r) { out[0] = r == null ? "null" : r; done.countDown(); }
                });
            }
        });
        try { done.await(10, TimeUnit.SECONDS); } catch (InterruptedException ignored) { }
        return out[0];
    }

    @Override
    public void onStart() {
        super.onStart();
        Bundle result = new Bundle();
        boolean pass = true;
        StringBuilder report = new StringBuilder();
        try {
            Intent i = new Intent(Intent.ACTION_MAIN);
            i.setClassName(getTargetContext(), "com.beamio.app.MainActivity");
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Activity a = startActivitySync(i);
            long deadline = System.currentTimeMillis() + 60_000;
            while (System.currentTimeMillis() < deadline
                    && !"true".equals(eval(a, "(typeof window.CashTreesAndroid==='object'&&document.readyState==='complete')"))) {
                Thread.sleep(500);
            }
            String ready = eval(a, "(typeof window.CashTreesAndroid==='object')");
            Log.i(TAG, "bridge ready=" + ready);
            if (!"true".equals(ready)) throw new IllegalStateException("bridge not ready");
            // Collectors: chat-module events (cashtreesandroid) and window.BeamioShellRecord replies (onmessage).
            eval(a, "(function(){window.__ah6={};window.__ah6sr=[];window.addEventListener('cashtreesandroid',function(e){try{var d=e.detail;"
                    + "if(d&&d.action==='chatModuleEvent'&&d.event){var k=(d.event.reqId===null||d.event.reqId===undefined)?'null':String(d.event.reqId);"
                    + "if(k==='null'||Number(k)>=" + BASE + "){(window.__ah6[k]=window.__ah6[k]||[]).push(JSON.stringify(d.event));}}}catch(x){}});"
                    + "if(window.BeamioShellRecord){window.BeamioShellRecord.onmessage=function(m){window.__ah6sr.push(String(m.data));};}"
                    // Chat sends: legacy CashTreesAndroid.chatModuleCommand when the build has it, else window.BeamioChat
                    // (its replies are re-dispatched as the same cashtreesandroid events so the collectors stay one).
                    + "window.__ah6chat=function(s){if(typeof window.CashTreesAndroid.chatModuleCommand==='function'){window.CashTreesAndroid.chatModuleCommand(s);}else{window.BeamioChat.postMessage(s);}};"
                    + "if(typeof window.CashTreesAndroid.chatModuleCommand!=='function'&&window.BeamioChat){window.BeamioChat.onmessage=function(m){"
                    + "try{window.dispatchEvent(new CustomEvent('cashtreesandroid',{detail:JSON.parse(m.data)}));}catch(x){}};}"
                    + "return 'armed';})()");
            // 1) Unknown names on the chat-module channel: exact code unknown_command (spec r3cs AS.3 / AU.2).
            for (int k = 0; k < NAMES.length; k++) {
                int reqId = BASE + k;
                Log.i(TAG, "send type=" + NAMES[k] + " reqId=" + reqId + " via window.CashTreesAndroid.chatModuleCommand");
                eval(a, "window.__ah6chat(JSON.stringify({type:'" + NAMES[k] + "',reqId:" + reqId + "}))");
            }
            // 1b) shellRecord* on the chat-module channel: not_supported, exactly once (r3cx §25.52AZ.1).
            for (int k = 0; k < SR_CHAT.length; k++) {
                eval(a, "window.__ah6chat(JSON.stringify({type:'" + SR_CHAT[k] + "',reqId:" + (BASE + 20 + k) + "}))");
            }
            // 2) hello capabilities (auditor: keep the release capability list as a file).
            eval(a, "window.__ah6chat(JSON.stringify({type:'hello',reqId:" + (BASE + 50) + "}))");
            // 3) Unparsable JSON on the chat-module channel: exactly one {type:ack, reqId:null, ok:false, error:bad_request} (AX.1).
            eval(a, "window.__ah6chat('{not json')");
            // 4) window.BeamioShellRecord (release injects it, AZ.4): an unknown shellRecord* name, then unparsable JSON.
            String srReady = eval(a, "(typeof window.BeamioShellRecord==='object'||typeof window.BeamioShellRecord==='function')");
            Log.i(TAG, "BeamioShellRecord present=" + srReady);
            if ("true".equals(srReady)) {
                eval(a, "window.BeamioShellRecord.postMessage(JSON.stringify({type:'shellRecordZzUnknown',reqId:" + (BASE + 60) + "}))");
                eval(a, "window.BeamioShellRecord.postMessage('{not json')");
                eval(a, "window.BeamioShellRecord.postMessage(JSON.stringify({type:'zzTopUnknown',reqId:" + (BASE + 61) + "}))");
            }
            long until = System.currentTimeMillis() + 15_000;
            JSONObject answers = new JSONObject();
            JSONArray sr = new JSONArray();
            while (System.currentTimeMillis() < until) {
                answers = new JSONObject(new JSONArray("[" + eval(a, "JSON.stringify(window.__ah6||{})") + "]").getString(0));
                sr = new JSONArray(new JSONArray("[" + eval(a, "JSON.stringify(window.__ah6sr||[])") + "]").getString(0));
                boolean all = answers.has("null") && answers.has(String.valueOf(BASE + 50));
                for (int k = 0; k < NAMES.length; k++) all &= answers.has(String.valueOf(BASE + k));
                for (int k = 0; k < SR_CHAT.length; k++) all &= answers.has(String.valueOf(BASE + 20 + k));
                if (all && (!"true".equals(srReady) || sr.length() >= 3)) break;
                Thread.sleep(300);
            }
            for (int k = 0; k < NAMES.length; k++) {
                String reqId = String.valueOf(BASE + k);
                JSONArray list = answers.optJSONArray(reqId);
                String raw = list == null ? "" : list.toString();
                Log.i(TAG, "answer type=" + NAMES[k] + " reqId=" + reqId + " raw=" + raw);
                report.append(NAMES[k]).append(" -> ").append(raw).append('\n');
                boolean ok = list != null && list.length() == 1;
                if (ok) {
                    JSONObject ev = new JSONObject(list.getString(0));
                    ok = "ack".equals(ev.optString("type")) && !ev.optBoolean("ok", true) && "unknown_command".equals(ev.optString("error"));
                }
                if (!ok) pass = false;
            }
            for (int k = 0; k < SR_CHAT.length; k++) {
                JSONArray list = answers.optJSONArray(String.valueOf(BASE + 20 + k));
                String raw = list == null ? "" : list.toString();
                Log.i(TAG, "answer chat " + SR_CHAT[k] + " raw=" + raw);
                report.append("chat ").append(SR_CHAT[k]).append(" -> ").append(raw).append('\n');
                boolean ok = list != null && list.length() == 1;
                if (ok) {
                    JSONObject ev = new JSONObject(list.getString(0));
                    ok = "ack".equals(ev.optString("type")) && !ev.optBoolean("ok", true) && "not_supported".equals(ev.optString("error"));
                }
                if (!ok) pass = false;
            }
            JSONArray hello = answers.optJSONArray(String.valueOf(BASE + 50));
            String helloRaw = hello == null ? "" : hello.toString();
            Log.i(TAG, "hello raw=" + helloRaw);
            report.append("hello -> ").append(helloRaw).append('\n');
            if (helloRaw.contains("identity.native-keys.v1")) { Log.i(TAG, "hello declares identity.native-keys.v1"); }
            JSONArray bad = answers.optJSONArray("null");
            String badRaw = bad == null ? "" : bad.toString();
            Log.i(TAG, "badJson chat raw=" + badRaw);
            report.append("badJson(chat) -> ").append(badRaw).append('\n');
            boolean badOk = bad != null && bad.length() == 1;
            if (badOk) {
                JSONObject ev = new JSONObject(bad.getString(0));
                badOk = "ack".equals(ev.optString("type")) && ev.isNull("reqId") && !ev.optBoolean("ok", true) && "bad_request".equals(ev.optString("error"));
            }
            if (!badOk) pass = false;
            Log.i(TAG, "BeamioShellRecord replies=" + sr.toString());
            report.append("BeamioShellRecord(shellRecordZzUnknown, badJson, zzTopUnknown) -> ").append(sr.toString()).append('\n');
            if (!"true".equals(srReady) || sr.length() != 3) pass = false;
            else {
                // Replies arrive in order; match by reqId where present. AU.1 / AW.1: ok:false with error, ack envelope.
                boolean uOk = false, bOk = false, tOk = false;
                for (int k = 0; k < sr.length(); k++) {
                    JSONObject r = new JSONObject(sr.getString(k));
                    boolean refused = "ack".equals(r.optString("type")) && !r.optBoolean("ok", true);
                    if (r.isNull("reqId")) bOk = refused && "bad_request".equals(r.optString("error"));
                    else if (r.optLong("reqId") == BASE + 60) uOk = refused && "unknown_command".equals(r.optString("error"));
                    else if (r.optLong("reqId") == BASE + 61) tOk = refused && "unknown_command".equals(r.optString("error"));
                }
                Log.i(TAG, "window checks unknownShellRecord=" + uOk + " badJson=" + bOk + " unknownTop=" + tOk);
                if (!uOk || !bOk || !tOk) pass = false;
            }
            // 4b) window.BeamioChat (scheme 1): hello -> ack ok:true with the same reqId; unparsable JSON -> bad_request.
            String bcReady = eval(a, "(typeof window.BeamioChat==='object'||typeof window.BeamioChat==='function')");
            Log.i(TAG, "BeamioChat present=" + bcReady);
            boolean bcOk = false;
            if ("true".equals(bcReady)) {
                eval(a, "(function(){window.__ah6bc=[];window.BeamioChat.onmessage=function(m){window.__ah6bc.push(String(m.data));};"
                        + "window.BeamioChat.postMessage(JSON.stringify({type:'hello',reqId:" + (BASE + 80) + "}));"
                        + "window.BeamioChat.postMessage('{not json');"
                        + "window.BeamioChat.postMessage(new ArrayBuffer(4));"
                        + "try{window.BeamioChat.postMessage({type:'hello',reqId:" + (BASE + 82) + "});window.__ah6bcObj='sent';}catch(e){window.__ah6bcObj='threw '+e.name;}"
                        + "return 'sent';})()");
                Thread.sleep(2500);
                JSONArray bc = new JSONArray(new JSONArray("[" + eval(a, "JSON.stringify(window.__ah6bc||[])") + "]").getString(0));
                Log.i(TAG, "BeamioChat raw=" + bc.toString());
                report.append("BeamioChat(hello, badJson, arrayBuffer) -> ").append(bc.toString()).append('\n');
                boolean helloOk = false, badOk2 = false; int helloCount = 0, badCount = 0;
                for (int k = 0; k < bc.length(); k++) {
                    JSONObject m = new JSONObject(bc.getString(k));
                    JSONObject ev = m.optJSONObject("event");
                    if (ev == null || !"chatModuleEvent".equals(m.optString("action"))) continue;
                    if (ev.optLong("reqId", -1) == BASE + 80 && "ack".equals(ev.optString("type"))) { helloCount++; helloOk = ev.optBoolean("ok", false); }
                    if (ev.isNull("reqId") && "bad_request".equals(ev.optString("error"))) badCount++;
                }
                // '{not json' and the ArrayBuffer (CT.5) each get exactly one bad_request; the object message is recorded only.
                String objOutcome = eval(a, "String(window.__ah6bcObj)");
                Log.i(TAG, "BeamioChat object postMessage -> " + objOutcome);
                report.append("BeamioChat(object) -> ").append(objOutcome).append('\n');
                // If the WebView accepted the object (coerced to a string), it is one more malformed message.
                badOk2 = badCount == ("sent".equals(objOutcome) ? 3 : 2);
                bcOk = helloOk && helloCount == 1 && badOk2;
                Log.i(TAG, "BeamioChat check hello=" + helloOk + " helloCount=" + helloCount + " badJson=" + badOk2);
            }
            if (!bcOk) pass = false;
            // 4c) window.BeamioShell: main frame accepted; gate and URL check answer on the channel; an appassets
            //     iframe is refused with origin_refused; sensitive methods on CashTreesAndroid only in a legacy build.
            String shReady = eval(a, "(typeof window.BeamioShell==='object'||typeof window.BeamioShell==='function')");
            Log.i(TAG, "BeamioShell present=" + shReady);
            boolean shOk = "true".equals(shReady);
            if (shOk) {
                eval(a, "(function(){window.__ah6sh=[];window.__ah6if=[];window.BeamioShell.onmessage=function(m){window.__ah6sh.push(String(m.data));};"
                        + "var P=function(o){window.BeamioShell.postMessage(JSON.stringify(o));};"
                        + "P({action:'queryInstalledApps',reqId:" + (BASE + 90) + ",args:{queries:[]}});"
                        + "P({action:'bindPushIdentity',reqId:" + (BASE + 91) + ",args:{}});"
                        + "P({action:'openURL',reqId:" + (BASE + 92) + ",args:{url:'https://x.example/p?privateKey=1'}});"
                        + "P({action:'chatModuleCommand',reqId:" + (BASE + 93) + "});"
                        // scanRecoveryQr removed -> unknown_command; notifyVoiceMicReady moved here -> gated (no_key in G0)
                        + "P({action:'scanRecoveryQr',reqId:" + (BASE + 95) + ",args:{requestId:'x'}});"
                        + "P({action:'notifyVoiceMicReady',reqId:" + (BASE + 96) + ",args:{}});"
                        // srcdoc: a same-origin (appassets) child frame, so the channel object is injected but isMainFrame is false.
                        + "var f=document.createElement('iframe');f.srcdoc='<p>ah6</p>';"
                        + "f.onload=function(){try{var w=f.contentWindow;window.__ah6ifHas=typeof w.BeamioShell;"
                        + "w.BeamioShell.onmessage=function(m){window.__ah6if.push(String(m.data));};"
                        + "w.BeamioShell.postMessage(JSON.stringify({action:'queryInstalledApps',reqId:" + (BASE + 94) + ",args:{}}));}"
                        + "catch(e){window.__ah6ifHas='err '+e.name;}};document.body.appendChild(f);return 'sent';})()");
                Thread.sleep(3500);
                JSONArray sh = new JSONArray(new JSONArray("[" + eval(a, "JSON.stringify(window.__ah6sh||[])") + "]").getString(0));
                JSONArray inf = new JSONArray(new JSONArray("[" + eval(a, "JSON.stringify(window.__ah6if||[])") + "]").getString(0));
                // evaluateJavascript returns JSON: strings arrive quoted, so strip the quotes before comparing.
                String ifHas = eval(a, "String(window.__ah6ifHas)").replace("\"", "");
                String legacyOpen = eval(a, "(window.CashTreesAndroid?typeof window.CashTreesAndroid.openURL:'nobridge')").replace("\"", "");
                String keptStatus = eval(a, "(window.CashTreesAndroid?typeof window.CashTreesAndroid.getEmbeddedPwaVersion:'nobridge')").replace("\"", "");
                Log.i(TAG, "BeamioShell raw=" + sh + " iframe(" + ifHas + ")=" + inf + " CashTreesAndroid.openURL=" + legacyOpen + " getEmbeddedPwaVersion=" + keptStatus);
                report.append("BeamioShell(main frame) -> ").append(sh.toString()).append('\n');
                report.append("BeamioShell(iframe ").append(ifHas).append(") -> ").append(inf.toString()).append('\n');
                report.append("CashTreesAndroid.openURL=").append(legacyOpen).append(" getEmbeddedPwaVersion=").append(keptStatus)
                        .append(" legacyExpected=").append(legacyExpected).append('\n');
                java.util.Map<Long, JSONObject> by = new java.util.HashMap<>();
                java.util.Map<Long, Integer> count = new java.util.HashMap<>();
                for (int k = 0; k < sh.length(); k++) {
                    JSONObject m = new JSONObject(sh.getString(k));
                    long id = m.optLong("reqId", -1); by.put(id, m); count.put(id, count.containsKey(id) ? count.get(id) + 1 : 1);
                }
                boolean once = sh.length() == 6;
                for (long id : new long[]{BASE + 90, BASE + 91, BASE + 92, BASE + 93, BASE + 95, BASE + 96}) once = once && Integer.valueOf(1).equals(count.get(id));
                JSONObject rq = by.get((long) (BASE + 95)), vm = by.get((long) (BASE + 96));
                boolean movedCmdsOk = rq != null && "unknown_command".equals(rq.optString("error"))
                        && vm != null && !vm.optBoolean("ok", true) && "no_key".equals(vm.optString("error"));
                String oldRecovery = eval(a, "(window.CashTreesAndroid?typeof window.CashTreesAndroid.scanRecoveryQr:'nobridge')").replace("\"", "");
                movedCmdsOk = movedCmdsOk && "undefined".equals(oldRecovery);
                Log.i(TAG, "BeamioShell scanRecoveryQr/notifyVoiceMicReady=" + movedCmdsOk + " CashTreesAndroid.scanRecoveryQr=" + oldRecovery);
                JSONObject q = by.get((long) (BASE + 90)), g = by.get((long) (BASE + 91)), u = by.get((long) (BASE + 92)), c = by.get((long) (BASE + 93));
                boolean qOk = q != null && q.optBoolean("ok") && q.optJSONArray("result") != null && "queryInstalledApps".equals(q.optString("action"));
                boolean gOk = g != null && !g.optBoolean("ok", true) && "no_key".equals(g.optString("error"));
                boolean uOk = u != null && !u.optBoolean("ok", true) && "key_shaped_content".equals(u.optString("error"));
                boolean cOk = c != null && "unknown_command".equals(c.optString("error"));
                boolean ifOk = inf.length() == 1 && "origin_refused".equals(new JSONObject(inf.getString(0)).optString("error"))
                        && new JSONObject(inf.getString(0)).optLong("reqId") == BASE + 94;
                boolean legOk = (legacyExpected ? "function" : "undefined").equals(legacyOpen) && "function".equals(keptStatus);
                // Every migrated name (23) on CashTreesAndroid: function only in a legacy build; every kept name (13): function.
                String[] migrated = {"openURL", "openInAppBrowser", "queryInstalledApps", "listInstalledWalletApps", "scanQr", "saveFile",
                        "requestCameraCapture", "bindPushIdentity", "postPgpCiphertext", "setNativeSiNodeRoster", "setNativeVoiceRelayNodes",
                        "cacheCallerAvatars", "prepareSystemCall", "cancelPreparedSystemCall", "startSystemCall", "reportIncomingSystemCall",
                        "endSystemCall", "queryIncomingCallOutcome", "notifyVoiceMicReady", "startNativeVoiceMic", "stopNativeVoiceMic",
                        "chatModuleCommand", "chatModuleSignResponse"};
                String[] kept = {"applyEmbeddedPwaUpdate", "getNfcStatus", "requestDeliveryHealth", "openDeliverySettings",
                        "dismissDeliveryHealthNotice", "getEmbeddedPwaVersion", "getEmbeddedPwaPendingVersion", "publishAppState",
                        "clearOfflineChatAlerts", "notifyBackgroundChat", "debugLog", "chatModuleAvailable", "chatModuleIsRunning"};
                String want = legacyExpected ? "function" : "undefined";
                StringBuilder tl = new StringBuilder();
                int migOk = 0, keptOk = 0;
                for (String n : migrated) {
                    String t = eval(a, "(typeof window.CashTreesAndroid['" + n + "'])").replace("\"", "");
                    tl.append(n).append('=').append(t).append(' ');
                    if (want.equals(t)) migOk++;
                }
                for (String n : kept) {
                    String t = eval(a, "(typeof window.CashTreesAndroid['" + n + "'])").replace("\"", "");
                    tl.append(n).append('=').append(t).append(' ');
                    if ("function".equals(t)) keptOk++;
                }
                Log.i(TAG, "typeof migrated " + migOk + "/" + migrated.length + " (want " + want + "), kept " + keptOk + "/" + kept.length);
                report.append("typeof CashTreesAndroid: ").append(tl.toString().trim()).append('\n');
                legOk = legOk && migOk == migrated.length && keptOk == kept.length;
                Log.i(TAG, "BeamioShell check once=" + once + " query=" + qOk + " gate=" + gOk + " url=" + uOk + " unknown=" + cOk
                        + " iframe=" + ifOk + " legacy=" + legOk);
                shOk = once && qOk && gOk && uOk && cOk && ifOk && legOk && movedCmdsOk;
            }
            if (!shOk) pass = false;
            // 5) Origin gate (scheme 2): once the top-level page is not the trusted origin, chatModuleCommand is
            //    refused by the shell with origin_refused, exactly once, reqId echoed.
            eval(a, "location.replace('about:blank');'nav'");
            Thread.sleep(2500);
            eval(a, "(function(){window.__ah6o=[];window.addEventListener('cashtreesandroid',function(e){try{var d=e.detail;"
                    + "if(d&&d.action==='chatModuleEvent'&&d.event){window.__ah6o.push(JSON.stringify(d.event));}}catch(x){}});return 'armed';})()");
            String hasBridge = eval(a, "(typeof window.CashTreesAndroid==='object'&&typeof window.CashTreesAndroid.chatModuleCommand==='function')");
            Log.i(TAG, "about:blank bridge present=" + hasBridge);
            if ("true".equals(hasBridge)) {
                eval(a, "window.CashTreesAndroid.chatModuleCommand(JSON.stringify({type:'hello',reqId:" + (BASE + 70) + "}))");
                Thread.sleep(1500);
            }
            JSONArray og = new JSONArray(new JSONArray("[" + eval(a, "JSON.stringify(window.__ah6o||[])") + "]").getString(0));
            Log.i(TAG, "originGate raw=" + og.toString());
            report.append("originGate(about:blank, hello) -> ").append(og.toString()).append('\n');
            // Without the legacy bridge there is no chatModuleCommand to call: nothing may arrive.
            boolean ogOk = legacyExpected ? og.length() == 1 : (og.length() == 0 && !"true".equals(hasBridge));
            if (ogOk && legacyExpected) {
                JSONObject ev = new JSONObject(og.getString(0));
                ogOk = "ack".equals(ev.optString("type")) && !ev.optBoolean("ok", true) && "origin_refused".equals(ev.optString("error"))
                        && ev.optLong("reqId") == BASE + 70;
            }
            Log.i(TAG, "originGate check=" + ogOk);
            if (!ogOk) pass = false;
            a.finish();
        } catch (Exception e) {
            pass = false;
            report.append("error ").append(e.getClass().getSimpleName()).append(' ').append(String.valueOf(e.getMessage()));
            Log.i(TAG, "error " + e.getClass().getSimpleName());
        }
        Log.i(TAG, "RESULT " + (pass ? "PASS" : "FAIL"));
        result.putString("ah6", report.toString());
        result.putString("result", pass ? "PASS" : "FAIL");
        finish(pass ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
    }
}
