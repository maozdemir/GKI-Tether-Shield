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
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Checks that the server on 127.0.0.1:64640 is the real daemon: it must
 * answer a fresh random nonce with HMAC-SHA256(token, "tshield-hello:" +
 * nonce), which requires the per-boot token only root and the daemon know.
 */
final class DaemonVerifier {
    private static final String HELLO_URL = "http://127.0.0.1:64640/api/hello?nonce=";
    private static final int TIMEOUT_MS = 1500;
    private static final int MAX_RESPONSE_BYTES = 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private DaemonVerifier() {}

    /** Blocking; call off the main thread. */
    static boolean verify(String token) {
        byte[] nonceBytes = new byte[32];
        RANDOM.nextBytes(nonceBytes);
        String nonce = toHex(nonceBytes);
        try {
            String proof = fetchProof(nonce);
            byte[] expected = hmac(token, "tshield-hello:" + nonce);
            byte[] actual = fromHex(proof);
            return actual != null && MessageDigest.isEqual(expected, actual);
        } catch (IOException | JSONException | GeneralSecurityException e) {
            return false;
        }
    }

    private static String fetchProof(String nonce) throws IOException, JSONException {
        HttpURLConnection conn = (HttpURLConnection) new URL(HELLO_URL + nonce).openConnection();
        try {
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setUseCaches(false);
            conn.setInstanceFollowRedirects(false);
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + conn.getResponseCode());
            }
            String body = readLimited(conn.getInputStream());
            return new JSONObject(body).getString("proof");
        } finally {
            conn.disconnect();
        }
    }

    private static String readLimited(InputStream in) throws IOException {
        try (InputStream stream = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256];
            int n;
            while ((n = stream.read(buf)) != -1) {
                if (out.size() + n > MAX_RESPONSE_BYTES) {
                    throw new IOException("response too large");
                }
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static byte[] hmac(String key, String message) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
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
