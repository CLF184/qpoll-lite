package com.qpoll.lite;

import android.app.Activity;
import android.os.Build;
import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.function.IntConsumer;

import org.json.JSONObject;

/** Runs the original Ink NFC Lab ST54L helper while Lite owns the foreground reader. */
final class St54lSession {
    private Process process;
    private boolean stopRequested;

    static boolean supported() {
        return Build.VERSION.SDK_INT == 37 && "haotian".equals(Build.DEVICE);
    }

    void start(Activity activity, String mode, File stopFile, int rfDelta,
               FrontSession.Events events, IntConsumer onExit) {
        String apk = quote(activity.getApplicationInfo().sourceDir);
        String snapshot = quote(new File(activity.getFilesDir(), "polling.snapshot").getAbsolutePath());
        boolean upload = "refresh".equals(mode);
        String command = "CLASSPATH=" + apk + " /system/bin/app_process /system/bin dev.inknfclab.RootProbe "
                + (upload ? "upload" : "probe") + " " + snapshot + " " + apk + " " + rfDelta;
        new Thread(() -> {
            int status = 1;
            try {
                if (stopFile.exists()) {
                    events.emit("CANCELLED", "已停止，未启动 ST54L 辅助进程");
                    status = 0;
                    return;
                }
                Process child = new ProcessBuilder("su", "-c", command).redirectErrorStream(true).start();
                attach(child);
                Thread output = new Thread(() -> readEvents(child, events), "st54l-output");
                output.start();
                long deadline = SystemClock.elapsedRealtime() + (upload ? 405000L : 80000L);
                while (!child.waitFor(200, TimeUnit.MILLISECONDS)) {
                    if (stopFile.exists()) stop();
                    if (SystemClock.elapsedRealtime() >= deadline) {
                        stop();
                        if (!child.waitFor(10, TimeUnit.SECONDS)) child.destroy();
                        events.emit("RESTORE_FAILED", "ST54L 辅助进程超时，恢复未确认；快照会在下轮重试恢复。");
                        break;
                    }
                }
                if (!child.isAlive()) status = child.exitValue();
                output.join(1500);
            } catch (Exception error) {
                events.emit("ERROR", "ST54L 辅助进程启动或运行失败：" + error);
                stop();
            } finally {
                onExit.accept(status);
            }
        }, "st54l-session").start();
    }

    synchronized void stop() {
        if (stopRequested) return;
        stopRequested = true;
        sendStop();
    }

    private synchronized void attach(Process child) {
        process = child;
        if (stopRequested) sendStop();
    }

    private void sendStop() {
        if (process == null) return;
        try {
            process.getOutputStream().write("stop\n".getBytes(StandardCharsets.UTF_8));
            process.getOutputStream().flush();
            process.getOutputStream().close();
        } catch (java.io.IOException ignored) { }
    }

    private static void readEvents(Process child, FrontSession.Events events) {
        try (BufferedReader input = new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) {
                try {
                    JSONObject event = new JSONObject(line);
                    events.emit(event.getString("event"), event.getString("message"));
                } catch (org.json.JSONException error) {
                    events.emit("ST54L_LOG", line);
                }
            }
        } catch (java.io.IOException error) {
            events.emit("ST54L_LOG", "日志流关闭：" + error.getMessage());
        }
    }

    private static String quote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }
}
