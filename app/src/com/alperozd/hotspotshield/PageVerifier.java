package com.alperozd.hotspotshield;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Fetches the dashboard page and returns it only if it is authentic: the
 * daemon must send HMAC-SHA256(token, "tshield-page:" + nonce + ":" + page)
 * for a fresh random nonce. The token is the per-boot secret that only root
 * and the daemon know, so a page served by another app that grabbed
 * 127.0.0.1:64640 is rejected and never runs inside this (trusted) app.
 */
final class PageVerifier {
    private static final String NONCE_HEADER = "X-Shield-Nonce";
    private static final String MAC_HEADER = "X-Shield-Page-MAC";
    private static final int TIMEOUT_MS = 2000;
    private static final int MAX_PAGE_BYTES = 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PageVerifier() {}

    /** Returns the verified page bytes, or null. Blocking; not on the main thread. */
    static byte[] fetchVerifiedPage(String pageUrl, String token) {
        byte[] nonceBytes = new byte[32];
        RANDOM.nextBytes(nonceBytes);
        String nonce = toHex(nonceBytes);
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(pageUrl).openConnection();
            try {
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setUseCaches(false);
                conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty(NONCE_HEADER, nonce);
                if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    return null;
                }
                byte[] actualMac = fromHex(conn.getHeaderField(MAC_HEADER));
                byte[] page = readLimited(conn.getInputStream());
                byte[] expectedMac = pageMac(token, nonce, page);
                return actualMac != null && MessageDigest.isEqual(expectedMac, actualMac) ? page : null;
            } finally {
                conn.disconnect();
            }
        } catch (IOException | GeneralSecurityException e) {
            return null;
        }
    }

    static byte[] pageMac(String token, String nonce, byte[] page) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update(("tshield-page:" + nonce + ":").getBytes(StandardCharsets.UTF_8));
        return mac.doFinal(page);
    }

    private static byte[] readLimited(InputStream in) throws IOException {
        try (InputStream stream = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = stream.read(buf)) != -1) {
                if (out.size() + n > MAX_PAGE_BYTES) {
                    throw new IOException("page too large");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /** Returns null for anything that is not an even-length hex string. */
    private static byte[] fromHex(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            return null;
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
