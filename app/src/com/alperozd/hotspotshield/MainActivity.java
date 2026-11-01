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
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;

/**
 * Zero-icon manager: shows the daemon's local dashboard in a WebView.
 *
 * <p>The daemon trusts this app (by UID) to change settings, so the app must
 * never show a page from anyone else: another app could bind 127.0.0.1:64640
 * while the daemon is down. Before every load the app checks that the server
 * proves knowledge of the per-boot token it was launched with (see
 * {@link DaemonVerifier}).
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
    private boolean destroyed;

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
        verifyThenLoad();
    }

    /** Loads the dashboard only after the real daemon has proven itself. */
    private void verifyThenLoad() {
        final String launchToken = token;
        new Thread(new Runnable() {
            @Override
            public void run() {
                final boolean verified = DaemonVerifier.verify(launchToken);
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        onVerified(verified);
                    }
                });
            }
        }, "daemon-verify").start();
    }

    private void onVerified(boolean verified) {
        if (destroyed) {
            return;
        }
        if (verified) {
            webView.loadUrl(DASHBOARD_URL);
            return;
        }
        if (++loadAttempts < MAX_LOAD_ATTEMPTS) {
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    verifyThenLoad();
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
        destroyed = true;
        handler.removeCallbacksAndMessages(null);
        if (webView != null) {
            webView.destroy();
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

    private static boolean isDashboard(Uri uri) {
        String host = uri.getHost();
        return "http".equals(uri.getScheme())
                && ("127.0.0.1".equals(host) || "localhost".equals(host))
                && uri.getPort() == DASHBOARD_PORT;
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
            if (isDashboard(uri)) {
                return false;
            }
            openExternally(uri);
            return true;
        }

        @Override
        public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
            // The daemon went away mid-load: re-verify before loading again.
            if (request.isForMainFrame() && ++loadAttempts < MAX_LOAD_ATTEMPTS) {
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        verifyThenLoad();
                    }
                }, RETRY_DELAY_MS);
            }
        }
    }
}
