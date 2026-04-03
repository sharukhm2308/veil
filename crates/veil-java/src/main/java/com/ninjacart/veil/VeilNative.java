package com.ninjacart.veil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * Native library loader for the Veil JNI bindings.
 *
 * <p>Loads {@code libveil_jni} (the Rust shared library built from
 * {@code crates/veil-jni}) which contains all cryptographic operations.
 *
 * <p>The library is loaded once on first access. The search order is:
 * <ol>
 *   <li>{@code veil.native.library.path} system property (explicit full path to the .dylib/.so/.dll)</li>
 *   <li>Bundled native library extracted from the JAR classpath ({@code /native/<os>/<arch>/})</li>
 *   <li>{@code java.library.path} / {@code LD_LIBRARY_PATH} (standard JNI fallback)</li>
 * </ol>
 *
 * <p>For most users, the bundled library inside the JAR is loaded automatically —
 * no system properties or library path configuration needed.
 */
final class VeilNative {

    private static volatile boolean loaded = false;

    private VeilNative() { }

    /**
     * Ensure the native library is loaded. Safe to call multiple times.
     *
     * @throws UnsatisfiedLinkError if the native library cannot be found
     */
    static void ensureLoaded() {
        if (loaded) return;

        synchronized (VeilNative.class) {
            if (loaded) return;

            // 1. Explicit path override
            String explicitPath = System.getProperty("veil.native.library.path");
            if (explicitPath != null && !explicitPath.isEmpty()) {
                System.load(explicitPath);
                loaded = true;
                return;
            }

            // 2. Extract from JAR classpath
            try {
                loadFromClasspath();
                loaded = true;
                return;
            } catch (Exception e) {
                // Fall through to system library path
            }

            // 3. Standard java.library.path / LD_LIBRARY_PATH
            System.loadLibrary("veil_jni");
            loaded = true;
        }
    }

    private static void loadFromClasspath() throws IOException {
        String os = normalizeOs();
        String arch = normalizeArch();
        String libName = libFileName();

        String resourcePath = "/native/" + os + "/" + arch + "/" + libName;
        InputStream in = VeilNative.class.getResourceAsStream(resourcePath);
        if (in == null) {
            throw new IOException("Native library not found in JAR: " + resourcePath);
        }

        // Extract to a temp file and load
        File tempDir = Files.createTempDirectory("veil-jni-").toFile();
        tempDir.deleteOnExit();
        File tempLib = new File(tempDir, libName);
        tempLib.deleteOnExit();

        try (InputStream is = in; OutputStream os2 = Files.newOutputStream(tempLib.toPath())) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                os2.write(buf, 0, n);
            }
        }

        System.load(tempLib.getAbsolutePath());
    }

    private static String normalizeOs() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        if (os.contains("linux")) return "linux";
        if (os.contains("win")) return "windows";
        return os;
    }

    private static String normalizeArch() {
        String arch = System.getProperty("os.arch", "").toLowerCase();
        if (arch.equals("aarch64") || arch.equals("arm64")) return "aarch64";
        if (arch.equals("amd64") || arch.equals("x86_64")) return "x86_64";
        return arch;
    }

    private static String libFileName() {
        String os = normalizeOs();
        if ("darwin".equals(os)) return "libveil_jni.dylib";
        if ("linux".equals(os)) return "libveil_jni.so";
        if ("windows".equals(os)) return "veil_jni.dll";
        return "libveil_jni.so";
    }
}
