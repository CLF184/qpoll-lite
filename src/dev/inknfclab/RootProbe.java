package dev.inknfclab;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.os.Looper;
import android.system.Os;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class RootProbe {
    private static final String FRIDA_VERSION = "17.24.0";
    private static final String COMPAT_READY = "INK_NFC_MIFARE_COMPAT_READY";
    private static final int UPLOAD_SECONDS = 340;
    private static FileChannel lockChannel;
    private static FileLock processLock;
    private final LinkedBlockingQueue<byte[]> replies = new LinkedBlockingQueue<>();
    private final CountDownLatch stop = new CountDownLatch(1);
    private volatile int expected = -1;
    private volatile int expectedOid = 1;
    private volatile boolean mutated;
    private volatile boolean restored;
    private NfcAdapter adapter;
    private Object callback;
    private Class<?> callbackClass;
    private boolean pollingPaused;
    private final ExecutorService callbacks = Executors.newSingleThreadExecutor();
    private File snapshot;
    private String apkPath;
    private int rfDelta;
    private File rfSnapshot;
    private Process traceProcess;
    private Thread traceThread;
    private volatile int tracePackets;
    private volatile boolean traceStopping;
    private int discoveries;
    private int activations;
    private int controllerErrors;

    public static void main(String[] args) {
        if ((args.length < 2 || args.length > 4) || !Arrays.asList("inspect", "rfinspect", "rftest", "probe", "upload", "restore", "compat").contains(args[0])) {
            event("ERROR", "无效参数");
            System.exit(2);
        }
        Looper.prepareMainLooper();
        try {
            File lock = new File("/data/local/tmp/ink-nfc-lab.lock");
            lockChannel = new FileOutputStream(lock, true).getChannel();
            Os.chmod(lock.getPath(), 0600);
            processLock = lockChannel.tryLock();
            if (processLock == null) throw new IllegalStateException("另一 NFC 辅助进程正在运行，请等其恢复完成");
        } catch (Throwable error) {
            event("ERROR", describe(error));
            System.exit(2);
        }
        RootProbe probe = new RootProbe();
        probe.snapshot = new File(args[1]);
        probe.apkPath = args.length >= 3 ? args[2] : null;
        probe.rfSnapshot = new File(args[1] + ".rf");
        try {
            probe.rfDelta = args.length == 4 ? Integer.parseInt(args[3]) : 0;
            RfConfig.validateDelta(probe.rfDelta);
            if (probe.rfDelta != 0 && !Arrays.asList("probe", "upload", "rftest").contains(args[0]))
                throw new IllegalArgumentException("此模式不允许调整 RF");
        } catch (Exception error) {
            event("ERROR", describe(error));
            System.exit(2);
        }
        Thread watchdog = new Thread(() -> {
            try { Thread.sleep(args[0].equals("upload") ? 390000 : 65000); } catch (InterruptedException ignored) { return; }
            event("ERROR", "辅助进程超过看门狗时限；保留恢复快照");
            if (probe.mutated && !probe.restored) probe.resetController();
            System.exit(124);
        }, "ink-nfc-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        Thread input = new Thread(() -> {
            try { new BufferedReader(new InputStreamReader(System.in)).readLine(); }
            catch (Exception ignored) {}
            probe.stop.countDown();
        }, "ink-nfc-stop");
        input.setDaemon(true);
        input.start();
        try { if (!args[0].equals("compat")) probe.prepareAdapter(); }
        catch (Throwable error) {
            event("ERROR", describe(error));
            System.exit(1);
        }
        new Thread(() -> {
            int status = probe.run(args[0]);
            if ((probe.mutated && !probe.restored) || probe.rfSnapshot.exists()) status = 1;
            event("EXIT", "辅助进程退出，代码 " + status);
            System.exit(status);
        }, "ink-nfc-worker").start();
        Looper.loop();
    }

    private int run(String mode) {
        byte[] original = null;
        boolean attempted = false;
        try {
            String hal = new String(Files.readAllBytes(new File("/odm/etc/libnfc-hal-st.conf").toPath()), StandardCharsets.UTF_8);
            if (!DeviceSupport.verifiedRootProfile(Build.DEVICE, Build.VERSION.SDK_INT) || !hal.contains("st21nfc") || !hal.contains("st54l"))
                throw new IllegalStateException("当前设备没有匹配的 Android 17 / ST54L 配置");
            if ("haotian".equals(Build.DEVICE)) verifyHaotianOverlay();
            event("ROOT", "root 辅助进程已启动，设备 " + Build.MODEL);
            if (mode.equals("compat")) {
                installMifareCompatibility();
                event("COMPAT_READY", "MIFARE 兼容拦截已启用，适用于同协议板子的所有 UID");
                return 0;
            }
            if (mode.equals("probe") || mode.equals("upload")) startTrace();
            initialize();
            if (rfSnapshot.exists()) {
                pausePolling();
                restoreRf();
            }
            if (mode.equals("rfinspect")) {
                for (int parameter = 2; parameter <= 4; parameter++) {
                    byte[] configuration = readRf(parameter);
                    event("RF_CONFIG", "PARAM=" + parameter + " APC=" + RfConfig.values(configuration)
                            + " RAW=" + Protocol.hex(configuration));
                }
                return 0;
            }
            pausePolling();
            if (mode.equals("rftest")) {
                applyRf();
                resumePolling();
                event("RF_TEST", "仅验证配置写入及恢复；10 秒，不发送板子刷新命令");
                stop.await(10, TimeUnit.SECONDS);
                return 0;
            }
            if (snapshot.exists()) {
                byte[] saved = Files.readAllBytes(snapshot.toPath());
                Protocol.validatePolling(saved);
                mutated = true;
                if (Arrays.equals(saved, readFrames())) confirmRestored();
                else restore(saved);
                mutated = false;
                restored = false;
                event("RECOVERED", "上次会话配置快照已恢复并核对");
            }
            if (mode.equals("restore")) {
                event("RESTORED", "没有待恢复快照，轮询已恢复");
                return 0;
            }
            original = readFrames();
            event("BASELINE", "当前轮询配置 " + Protocol.hex(original));
            if (mode.equals("inspect")) {
                event("CHECKED", "厂商 NCI 查询成功；未设置自定义帧");
                return 0;
            }
            if (stop.getCount() == 0) {
                event("CANCELLED", "设置前收到停止请求");
                return 0;
            }
            if (mode.equals("upload") || mode.equals("probe")) {
                // Restore earlier snapshots first, then keep Frida startup outside the haotian pause window.
                resumePolling();
                installMifareCompatibility();
                event("MIFARE_COMPAT", "MIFARE 重选拦截已注入，无 UID 白名单；240 秒后自动卸载");
                if (stop.getCount() == 0) return 0;
                pausePolling();
                original = readFrames();
            }
            save(original);
            attempted = true;
            mutated = true;
            applyRf();
            setFrames(Protocol.polling7A());
            byte[] readback = readFrames();
            if (!Arrays.equals(readback, Protocol.polling7A()))
                throw new IllegalStateException("设置读回不匹配 " + Protocol.hex(readback));
            resumePolling();
            int seconds = mode.equals("upload") ? UPLOAD_SECONDS : 25;
            event("READY", "7A 短帧配置已被接口接受且读回一致；会话上限 " + seconds
                    + " 秒。射频发射尚未独立确认");
            stop.await(seconds, TimeUnit.SECONDS);
            return 0;
        } catch (Throwable error) {
            event("ERROR", describe(error));
            return 1;
        } finally {
            if (rfSnapshot.exists() && adapter != null && callback != null) {
                try { pausePolling(); restoreRf(); }
                catch (Throwable error) { event("RECOVERY_FAILED", "射频恢复未确认，保留快照，请勿继续实验：" + describe(error)); }
            }
            if (attempted && original != null) {
                try {
                    pausePolling();
                    restore(original);
                }
                catch (Throwable error) {
                    event("RECOVERY_FAILED", "配置恢复未确认：" + describe(error));
                }
            }
            if (mutated && !restored) resetController();
            if (adapter != null) {
                try { resumePolling(); }
                catch (Throwable error) { event("ERROR", "恢复轮询调用失败：" + describe(error)); }
                if (callback != null) {
                    try { NfcAdapter.class.getMethod("unregisterNfcVendorNciCallback", callbackClass).invoke(adapter, callback); }
                    catch (Throwable error) { event("ERROR", "注销回调失败：" + describe(error)); }
                }
            }
            callbacks.shutdownNow();
            stopTrace();
        }
    }

    private static void verifyHaotianOverlay() throws Exception {
        String service = sha256("/odm/bin/hw/android.hardware.nfc-service-st");
        String apk = sha256("/system/app/Nfc_st/Nfc_st.apk");
        if (!"0FC24CEA3181A0C7F68F31CD9673AAC1FA31BFCFC541D0438AC807ECF444FE26".equals(service)
                || !"6D9A75FB00C5CA1D942161D118CF0CC224AED3992703D88508503186BE8BF02B".equals(apk)) {
            throw new IllegalStateException("请停用旧 nfc-odm17，启用 haotian A17 ODM 模块并重启。需要原厂 Android 17 NFC APK。");
        }
    }

    private static String sha256(String path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(new File(path).toPath())) {
            byte[] buffer = new byte[32768];
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return Protocol.hex(digest.digest());
    }

    private void installMifareCompatibility() throws Exception {
        if (apkPath == null) throw new IllegalStateException("缺少 APK 路径，无法加载 MIFARE 兼容组件");
        File directory = new File("/data/local/tmp");
        File injector = new File(directory, "ink-nfc-frida-inject-" + FRIDA_VERSION);
        File script = new File(directory, "ink-nfc-mifare-compat.js");
        if (!injector.isFile() || injector.length() == 0)
            extractAsset("frida-inject", injector, 0700);
        extractAsset("mifare-compat.js", script, 0600);
        ensureFridaServer();
        String version = runCommand(10000, injector.getPath(), "--version");
        if (!version.contains(FRIDA_VERSION))
            throw new IllegalStateException("Frida 注入器版本不匹配，要求 " + FRIDA_VERSION + "，实际：" + version.trim());
        String pidOutput = runCommand(10000, "/system/bin/pidof", "com.android.nfc").trim();
        if (pidOutput.isEmpty()) throw new IllegalStateException("找不到 Android NFC 服务进程");
        String pid = pidOutput.split("\\s+")[0];
        String output;
        try {
            output = runCommand(20000, injector.getPath(), "--pid", pid, "--script", script.getPath(), "--eternalize");
        } catch (Exception error) {
            String replacement = "";
            for (int attempt = 0; attempt < 10; attempt++) {
                Thread.sleep(200);
                String current = runCommand(5000, "/system/bin/sh", "-c", "pidof com.android.nfc 2>/dev/null || true").trim();
                if (!current.isEmpty() && !current.split("\\s+")[0].equals(pid)) {
                    replacement = current.split("\\s+")[0];
                    break;
                }
            }
            if (replacement.isEmpty()) throw error;
            event("COMPAT_RETRY", "NFC 服务已重启，使用新进程 " + replacement + " 重试一次兼容注入");
            output = runCommand(20000, injector.getPath(), "--pid", replacement, "--script", script.getPath(), "--eternalize");
        }
        if (!output.contains(COMPAT_READY))
            throw new IllegalStateException("MIFARE 兼容注入未确认：" + output.trim());
    }

    private void ensureFridaServer() throws Exception {
        String serverPid = runCommand(5000, "/system/bin/sh", "-c", "pidof ink-frida-server 2>/dev/null || true").trim();
        if (!serverPid.isEmpty()) return;
        File server = new File("/data/local/tmp/ink-frida-server");
        if (!server.isFile()) throw new IllegalStateException("手机未安装配套 Frida 17.24.0 服务端");
        String version = runCommand(10000, server.getPath(), "--version");
        if (!version.contains(FRIDA_VERSION))
            throw new IllegalStateException("Frida 服务端版本不匹配，要求 " + FRIDA_VERSION + "，实际：" + version.trim());
        runCommand(10000, server.getPath(), "--listen=127.0.0.1:27042", "--policy-softener=internal", "--disable-preload", "--daemonize");
        for (int attempt = 0; attempt < 20; attempt++) {
            Thread.sleep(100);
            serverPid = runCommand(5000, "/system/bin/sh", "-c", "pidof ink-frida-server 2>/dev/null || true").trim();
            if (!serverPid.isEmpty()) return;
        }
        throw new IllegalStateException("Frida 服务端启动后未能确认运行");
    }

    private void extractAsset(String name, File destination, int mode) throws Exception {
        try (ZipFile apk = new ZipFile(apkPath)) {
            ZipEntry entry = apk.getEntry("assets/" + name);
            if (entry == null) throw new IllegalStateException("APK 缺少兼容资源：" + name);
            try (InputStream input = apk.getInputStream(entry); FileOutputStream output = new FileOutputStream(destination)) {
                byte[] buffer = new byte[32768];
                int count;
                while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
                output.getFD().sync();
            }
        }
        Os.chmod(destination.getPath(), mode);
    }

    private static String runCommand(long timeoutMs, String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) captured.write(buffer, 0, count);
            } catch (Exception ignored) {}
        }, "ink-nfc-command-output");
        reader.start();
        if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            reader.join(1000);
            throw new IllegalStateException("命令超时：" + command[0]);
        }
        reader.join(1000);
        String output = new String(captured.toByteArray(), StandardCharsets.UTF_8);
        if (process.exitValue() != 0) throw new IllegalStateException("命令失败：" + command[0] + " · " + output.trim());
        return output;
    }

    private void prepareAdapter() throws Exception {
        Class<?> managerClass = Class.forName("android.nfc.NfcServiceManager");
        Class<?> initializer = Class.forName("android.nfc.NfcFrameworkInitializer");
        if (initializer.getMethod("getNfcServiceManager").invoke(null) == null)
            initializer.getMethod("setNfcServiceManager", managerClass).invoke(null, managerClass.getConstructor().newInstance());
        Class<?> threadClass = Class.forName("android.app.ActivityThread");
        Object thread = threadClass.getMethod("systemMain").invoke(null);
        Context context = (Context) threadClass.getDeclaredMethod("getSystemContext").invoke(thread);
        adapter = NfcAdapter.getDefaultAdapter(context);
        if (adapter == null || !adapter.isEnabled()) throw new IllegalStateException("请先打开手机 NFC");
    }

    private void initialize() throws Exception {
        callbackClass = Class.forName("android.nfc.NfcAdapter$NfcVendorNciCallback");
        callback = Proxy.newProxyInstance(callbackClass.getClassLoader(), new Class<?>[]{callbackClass}, (proxy, method, args) -> {
            if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
            if (method.getName().equals("equals")) return proxy == args[0];
            if (method.getName().equals("toString")) return "InkNfcVendorCallback";
            if (method.getName().equals("onVendorNciNotification")) {
                event("VENDOR_NTF", "GID=" + args[0] + " OID=" + args[1] + " RAW="
                        + Protocol.hex((byte[]) args[2]) + "（控制器通知，不自动视为板子回复）");
            }
            if (method.getName().equals("onVendorNciResponse") && (Integer) args[0] == 15 && (Integer) args[1] == expectedOid) {
                byte[] response = (byte[]) args[2];
                if (response != null && response.length > 0 && expected >= 0
                        && (expectedOid == 2 || (response[0] & 255) == expected))
                    replies.offer(response.clone());
            }
            return null;
        });
        NfcAdapter.class.getMethod("registerNfcVendorNciCallback", java.util.concurrent.Executor.class, callbackClass)
                .invoke(adapter, callbacks, callback);
        event("CONNECTED", "厂商 NCI 回调已注册");
    }

    private byte[] exchange(int subcommand, byte[] data) throws Exception {
        return exchange(1, subcommand, data);
    }

    private byte[] exchange(int oid, int subcommand, byte[] data) throws Exception {
        byte[] command = new byte[data.length + 1];
        command[0] = (byte) subcommand;
        System.arraycopy(data, 0, command, 1, data.length);
        replies.clear();
        expected = subcommand;
        expectedOid = oid;
        try {
            Method send = NfcAdapter.class.getMethod("sendVendorNciMessage", int.class, int.class, int.class, byte[].class);
            event("NCI_TX", "GID=0F OID=" + oid + " " + Protocol.hex(command));
            int result = (Integer) send.invoke(adapter, 1, 15, oid, command);
            if (result != 0) throw new IllegalStateException("厂商命令返回 " + result);
            byte[] response = replies.poll(2, TimeUnit.SECONDS);
            if (response == null) throw new IllegalStateException("厂商响应超时；未得到确认");
            event("NCI_RX", Protocol.hex(response));
            if (oid == 2) {
                if (response[0] != 0)
                    throw new IllegalStateException("ST 配置命令未返回成功状态 " + Protocol.hex(response));
                return Arrays.copyOfRange(response, 1, response.length);
            }
            if (response.length < 2 || response[1] != 0)
                throw new IllegalStateException("ST 命令未返回成功状态 " + Protocol.hex(response));
            return Arrays.copyOfRange(response, 2, response.length);
        } finally {
            expected = -1;
        }
    }

    private void startTrace() {
        try {
            File trace = new File(snapshot.getPath() + ".trace.txt");
            FileOutputStream output = new FileOutputStream(trace);
            Os.chmod(trace.getPath(), 0600);
            android.system.StructStat owner = Os.stat(snapshot.getParent());
            Os.chown(trace.getPath(), owner.st_uid, owner.st_gid);
            traceProcess = new ProcessBuilder("/system/bin/logcat", "-T", "1", "-v", "brief", "StNfcHal:D", "*:S")
                    .redirectErrorStream(true).start();
            traceThread = new Thread(() -> {
                NciTrace parser = new NciTrace();
                try (FileOutputStream file = output;
                     BufferedReader input = new BufferedReader(new InputStreamReader(traceProcess.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = input.readLine()) != null) {
                        file.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                        String packet = parser.accept(line);
                        if (packet != null) {
                            tracePackets++;
                            if (packet.contains("RAW=6103")) discoveries++;
                            if (packet.contains("RAW=6105")) activations++;
                            if (packet.contains("RAW=6007") || packet.contains("RAW=6008")) controllerErrors++;
                            if (tracePackets <= 80 || !packet.contains("ST 固件调试通知")) event("HAL_NCI", packet);
                            if (tracePackets == 81) event("TRACE_LIMIT", "固件调试通知仅显示前 80 包；完整底层日志仍保存，可分享");
                        }
                    }
                } catch (Exception error) {
                    if (!traceStopping) event("TRACE_ERROR", "底层日志流：" + describe(error));
                }
            }, "ink-nfc-hal-trace");
            traceThread.start();
            event("TRACE_STARTED", "只读采集 ST HAL 日志及厂商通知；不更改系统日志配置。收发方向指主机与 NFC 控制器");
        } catch (Exception error) { event("TRACE_ERROR", "底层日志不可用：" + describe(error)); }
    }

    private void stopTrace() {
        if (traceProcess == null) return;
        traceStopping = true;
        traceProcess.destroy();
        try { traceThread.join(1500); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        event("TRACE_SUMMARY", "NCI 包 " + tracePackets + " 个；底层目标发现 " + discoveries
                + " 次，接口激活 " + activations + " 次，控制器错误 " + controllerErrors
                + " 次。厂商调试通知未解码；底层目标尚未核实身份");
    }

    private void pausePolling() throws Exception {
        if (pollingPaused) return;
        Object extension = NfcAdapter.class.getMethod("getNfcOemExtension").invoke(adapter);
        Method pause = extension.getClass().getMethod("pausePolling", long.class);
        long timeoutMs = "haotian".equals(Build.DEVICE) ? 10000L : 30000L;
        for (int attempt = 0; attempt < 8; attempt++) {
            int result = (Integer) pause.invoke(extension, timeoutMs);
            if (result == 1) {
                pollingPaused = true;
                event("PAUSED", "已暂停轮询，连续执行配置事务");
                return;
            }
            if (result != 2) throw new IllegalStateException("暂停轮询返回 " + result);
            Thread.sleep(120);
        }
        throw new IllegalStateException("未能建立轮询暂停状态；未开始配置事务");
    }

    private void resumePolling() throws Exception {
        if (!pollingPaused) return;
        if ("haotian".equals(Build.DEVICE)) {
            Object extension = NfcAdapter.class.getMethod("getNfcOemExtension").invoke(adapter);
            int result = (Integer) extension.getClass().getMethod("resumePolling").invoke(extension);
            if (result != 1 && result != 2) throw new IllegalStateException("恢复轮询返回 " + result);
        } else {
            NfcAdapter.class.getMethod("resumePolling").invoke(adapter);
        }
        pollingPaused = false;
        event("RESUMED", "已请求恢复轮询");
    }

    private byte[] readFrames() throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                byte[] frames = exchange(21, new byte[0]);
                Protocol.validatePolling(frames);
                return frames;
            } catch (Exception error) {
                last = error;
                if (attempt < 2) Thread.sleep(300);
            }
        }
        throw last;
    }

    private void setFrames(byte[] frames) throws Exception {
        Protocol.validatePolling(frames);
        exchange(19, frames);
    }

    private byte[] readRf(int parameter) throws Exception {
        return RfConfig.parse(parameter, exchange(2, 3, new byte[]{0, 16, 1, (byte) parameter}));
    }

    private void writeRf(int parameter, byte[] configuration) throws Exception {
        RfConfig.validate(configuration);
        byte[] command = new byte[configuration.length + 5];
        command[1] = 16;
        command[2] = 1;
        command[3] = (byte) parameter;
        command[4] = (byte) configuration.length;
        System.arraycopy(configuration, 0, command, 5, configuration.length);
        exchange(2, 4, command);
        exchange(2, 10, new byte[0]);
        if (!Arrays.equals(configuration, readRf(parameter)))
            throw new IllegalStateException("RF 参数 " + parameter + " 写入读回不一致");
    }

    private void applyRf() throws Exception {
        if (rfDelta == 0) return;
        byte[][] original = new byte[3][];
        for (int index = 0; index < 3; index++) original[index] = readRf(index + 2);
        if (rfSnapshot.exists()) throw new IllegalStateException("存在未恢复 RF 快照");
        File temporary = new File(rfSnapshot.getPath() + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            Os.chmod(temporary.getPath(), 0600);
            for (byte[] configuration : original) output.write(configuration);
            output.getFD().sync();
        }
        if (!temporary.renameTo(rfSnapshot)) throw new IllegalStateException("RF 快照保存失败");
        for (int index = 0; index < 3; index++) {
            byte[] adjusted = RfConfig.adjust(original[index], rfDelta);
            writeRf(index + 2, adjusted);
            event("RF_APPLIED", "PARAM=" + (index + 2) + " APC " + RfConfig.values(original[index])
                    + " → " + RfConfig.values(adjusted) + "；仅实验档，不代表实测功率");
        }
    }

    private void restoreRf() throws Exception {
        byte[] saved = Files.readAllBytes(rfSnapshot.toPath());
        if (saved.length != RfConfig.LENGTH * 3) throw new IllegalStateException("RF 恢复快照长度错误");
        byte[][] configurations = new byte[3][];
        for (int index = 0; index < 3; index++) {
            configurations[index] = Arrays.copyOfRange(saved, index * RfConfig.LENGTH, (index + 1) * RfConfig.LENGTH);
            RfConfig.validate(configurations[index]);
        }
        for (int index = 0; index < 3; index++) writeRf(index + 2, configurations[index]);
        if (!rfSnapshot.delete()) throw new IllegalStateException("RF 已恢复，但恢复快照删除失败");
        event("RF_RESTORED", "三组原始 APC 参数已恢复并逐字节读回确认");
    }

    private void save(byte[] frames) throws Exception {
        File temporary = new File(snapshot.getPath() + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            Os.chmod(temporary.getPath(), 0600);
            output.write(frames);
            output.getFD().sync();
        }
        if (!temporary.renameTo(snapshot)) throw new IllegalStateException("保存恢复快照失败");
        event("SAVED", "原始轮询配置已保存");
    }

    private void restore(byte[] frames) throws Exception {
        setFrames(frames);
        if (!Arrays.equals(frames, readFrames())) throw new IllegalStateException("恢复读回不一致");
        confirmRestored();
    }

    private void confirmRestored() {
        restored = true;
        if (snapshot.exists() && !snapshot.delete()) event("ERROR", "恢复成功，但快照文件未删除");
        event("RESTORED", "原始轮询配置恢复成功，读回一致");
    }

    private void resetController() {
        try {
            Process disable = new ProcessBuilder("/system/bin/svc", "nfc", "disable").start();
            if (!disable.waitFor(5, TimeUnit.SECONDS)) disable.destroy();
            Thread.sleep(1500);
            Process enable = new ProcessBuilder("/system/bin/svc", "nfc", "enable").start();
            if (!enable.waitFor(5, TimeUnit.SECONDS)) enable.destroy();
            event("RESET", "已请求关闭并开启 NFC；快照保留，不能据此宣称配置恢复已验证");
        } catch (Throwable error) { event("ERROR", "NFC 重启失败：" + describe(error)); }
    }

    private static String describe(Throwable error) {
        while (error.getCause() != null) error = error.getCause();
        return error.getClass().getSimpleName() + ": " + error.getMessage();
    }

    private static synchronized void event(String type, String message) {
        try {
            JSONObject data = new JSONObject();
            data.put("event", type);
            data.put("message", message);
            System.out.println(data);
            System.out.flush();
        } catch (Exception ignored) {}
    }
}
