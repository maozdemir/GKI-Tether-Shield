package com.alperozd.hotspotshield;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** Zero-icon manager: shows the daemon's local dashboard in a WebView. */
public class MainActivity extends Activity {
    private static final String DASHBOARD_URL = "http://127.0.0.1:64640/";
    private static final int DASHBOARD_PORT = 64640;
    // The Magisk action may start the daemon right before launching us.
    private static final int MAX_LOAD_RETRIES = 10;
    private static final long RETRY_DELAY_MS = 1000;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private WebView webView;
    private int loadRetries;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Modern Edge-to-Edge Dark Status Bar
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(Color.parseColor("#0F172A"));
        window.setNavigationBarColor(Color.parseColor("#0F172A"));

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#0F172A"));

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);

        webView.setWebViewClient(new DashboardClient());
        webView.loadUrl(DASHBOARD_URL);

        setContentView(webView);
    }

    // Pause the page (its JavaScript timers poll the daemon) while the app
    // is in the background; Android does not do this for a WebView by itself.
    @Override
    protected void onResume() {
        super.onResume();
        webView.onResume();
        webView.resumeTimers();
    }

    @Override
    protected void onPause() {
        webView.onPause();
        webView.pauseTimers();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        webView.destroy();
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
            if (!request.isForMainFrame() || loadRetries >= MAX_LOAD_RETRIES) {
                return;
            }
            loadRetries++;
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    webView.loadUrl(DASHBOARD_URL);
                }
            }, RETRY_DELAY_MS);
        }
    }
}
