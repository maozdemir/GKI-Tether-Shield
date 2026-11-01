package com.alperozd.hotspotshield;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;
import java.io.ByteArrayInputStream;
import java.util.Collections;

/**
 * Zero-icon manager: shows the daemon's local dashboard in a WebView.
 *
 * <p>The daemon trusts this app (by UID) to change settings, so no page other
 * than the daemon's own may ever run here: another app could bind
 * 127.0.0.1:64640 while the daemon is down. Every main-frame load of the
 * dashboard is fetched natively and only handed to the WebView if its MAC
 * verifies against the per-boot token (see {@link PageVerifier}). The
 * activity is not exported; only root (the module's action.sh) can start it
 * and supply the token.
 */
public class MainActivity extends Activity {
    static final String EXTRA_TOKEN = "token";
    private static final String DASHBOARD_URL = "http://127.0.0.1:64640/";
    private static final int DASHBOARD_PORT = 64640;
    // The Magisk action may start the daemon right before launching us.
    private static final int MAX_LOAD_ATTEMPTS = 10;
    private static final long RETRY_DELAY_MS = 1000;
    private static final int BACKGROUND = Color.parseColor("#0F172A");

    private final Handler handler = new Handler(Looper.getMainLooper());
    private WebView webView;
    private String token;
    private int loadAttempts;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Modern Edge-to-Edge Dark Status Bar
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(BACKGROUND);
        window.setNavigationBarColor(BACKGROUND);

        token = getIntent().getStringExtra(EXTRA_TOKEN);
        if (token == null || token.isEmpty()) {
            showMessage("Open Hotspot Shield from the Action button in Magisk, KernelSU or APatch.");
            return;
        }

        webView = new WebView(this);
        webView.setBackgroundColor(BACKGROUND);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);

        webView.setWebViewClient(new DashboardClient());
        setContentView(webView);
        webView.loadUrl(DASHBOARD_URL);
    }

    private void retryOrGiveUp() {
        if (webView == null) {
            return;
        }
        if (++loadAttempts < MAX_LOAD_ATTEMPTS) {
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    if (webView != null) {
                        webView.loadUrl(DASHBOARD_URL);
                    }
                }
            }, RETRY_DELAY_MS);
        } else {
            showMessage("The Hotspot Shield service is not responding.\n"
                    + "Reopen it from your root manager's Action button.");
        }
    }

    private void showMessage(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(Color.WHITE);
        view.setBackgroundColor(BACKGROUND);
        view.setGravity(Gravity.CENTER);
        view.setPadding(48, 48, 48, 48);
        setContentView(view);
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
    }

    // Pause the page (its JavaScript timers poll the daemon) while the app
    // is in the background; Android does not do this for a WebView by itself.
    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            webView.onResume();
            webView.resumeTimers();
        }
    }

    @Override
    protected void onPause() {
        if (webView != null) {
            webView.onPause();
            webView.pauseTimers();
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    private static boolean isDashboardHost(Uri uri) {
        String host = uri.getHost();
        return "http".equals(uri.getScheme())
                && ("127.0.0.1".equals(host) || "localhost".equals(host))
                && uri.getPort() == DASHBOARD_PORT;
    }

    private static WebResourceResponse errorResponse(int status, String reason) {
        return new WebResourceResponse("text/plain", "utf-8", status, reason,
                Collections.<String, String>emptyMap(), new ByteArrayInputStream(new byte[0]));
    }

    /** Opens http(s) links (GitHub, releases) in the user's browser. */
    private void openExternally(Uri uri) {
        String scheme = uri.getScheme();
        if (!"https".equals(scheme) && !"http".equals(scheme)) {
            return; // never hand javascript:, intent:, file: etc. to other apps
        }
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, uri));
        } catch (ActivityNotFoundException ignored) {
            // No browser installed; nothing sensible to do.
        }
    }

    private final class DashboardClient extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            if (isDashboardHost(uri)) {
                return false;
            }
            openExternally(uri);
            return true;
        }

        // Runs on a background thread for every request. Only main-frame page
        // loads are taken over; the page's own fetch() calls go to the network
        // as data (a swapped server could only feed it numbers, never code).
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            if (!request.isForMainFrame() || !isDashboardHost(uri)) {
                return null;
            }
            String path = uri.getPath();
            if (!"GET".equals(request.getMethod()) || !(path == null || path.isEmpty() || "/".equals(path))) {
                return errorResponse(404, "Not Found");
            }
            byte[] page = PageVerifier.fetchVerifiedPage(DASHBOARD_URL, token);
            if (page == null) {
                return errorResponse(503, "Service Unavailable");
            }
            return new WebResourceResponse("text/html", "utf-8", 200, "OK",
                    Collections.singletonMap("Cache-Control", "no-store"), new ByteArrayInputStream(page));
        }

        @Override
        public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse response) {
            if (request.isForMainFrame() && response.getStatusCode() == 503) {
                retryOrGiveUp();
            }
        }

        @Override
        public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
            if (request.isForMainFrame()) {
                retryOrGiveUp();
            }
        }
    }
}
