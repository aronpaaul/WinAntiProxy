package im.aronpaul.winantiproxy.detect.intel;

import im.aronpaul.winantiproxy.config.Settings;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

public final class IntelService {

    private static final Pattern PROXYCHECK_STATUS = Pattern.compile("\"status\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PROXYCHECK_PROXY_STR = Pattern.compile("\"proxy\"\\s*:\\s*\"(yes|no)\"");
    private static final Pattern PROXYCHECK_PROXY_BOOL = Pattern.compile("\"proxy\"\\s*:\\s*(true|false)");
    private static final Pattern PROXYCHECK_ANON_STR = Pattern.compile("\"anonymous\"\\s*:\\s*\"(yes|no)\"");
    private static final Pattern PROXYCHECK_ANON_BOOL = Pattern.compile("\"anonymous\"\\s*:\\s*(true|false)");
    private static final Pattern PROXYCHECK_VPN_STR = Pattern.compile("\"vpn\"\\s*:\\s*\"(yes|no)\"");
    private static final Pattern PROXYCHECK_VPN_BOOL = Pattern.compile("\"vpn\"\\s*:\\s*(true|false)");
    private static final Pattern PROXYCHECK_TOR_STR = Pattern.compile("\"tor\"\\s*:\\s*\"(yes|no)\"");
    private static final Pattern PROXYCHECK_TOR_BOOL = Pattern.compile("\"tor\"\\s*:\\s*(true|false)");
    private static final Pattern PROXYCHECK_HOSTING_STR = Pattern.compile("\"hosting\"\\s*:\\s*\"(yes|no)\"");
    private static final Pattern PROXYCHECK_HOSTING_BOOL = Pattern.compile("\"hosting\"\\s*:\\s*(true|false)");
    private static final Pattern PROXYCHECK_NETWORK_TYPE = Pattern.compile("\"network\"\\s*:\\s*\\{.*?\"type\"\\s*:\\s*\"([^\"]+)\"", Pattern.DOTALL);
    private static final Pattern PROXYCHECK_COUNTRY = Pattern.compile("\"country_code\"\\s*:\\s*\"([A-Za-z]{2})\"");
    private static final Pattern PROXYCHECK_ISO = Pattern.compile("\"isocode\"\\s*:\\s*\"([A-Za-z]{2})\"");
    private static final Pattern PROXYCHECK_RISK = Pattern.compile("\"risk\"\\s*:\\s*\"?(\\d+)\"?");

    private static final Pattern IPQS_SUCCESS = Pattern.compile("\"success\"\\s*:\\s*(true|false)");
    private static final Pattern IPQS_PROXY = Pattern.compile("\"proxy\"\\s*:\\s*(true|false)");
    private static final Pattern IPQS_VPN = Pattern.compile("\"vpn\"\\s*:\\s*(true|false)");
    private static final Pattern IPQS_TOR = Pattern.compile("\"tor\"\\s*:\\s*(true|false)");
    private static final Pattern IPQS_FRAUD = Pattern.compile("\"fraud_score\"\\s*:\\s*(\\d+)");
    private static final Pattern IPQS_COUNTRY = Pattern.compile("\"country_code\"\\s*:\\s*\"([A-Za-z]{2})\"");
    private static final Pattern IPQS_CONN = Pattern.compile("\"connection_type\"\\s*:\\s*\"([^\"]+)\"");

    private final JavaPlugin plugin;
    private final Settings config;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public IntelService(JavaPlugin plugin, Settings config) {
        this.plugin = plugin;
        this.config = config;
    }

    public boolean isBlocked(InetAddress address) {
        if (address == null || !config.getIntel().isEnabled()) {
            return false;
        }
        String key = address.getHostAddress();
        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(key);
        if (cached != null && cached.expiresAt > now) {
            return cached.result.shouldBlock(config.getIntel());
        }
        IntelResult result = query(address);
        long ttlMs = config.getIntel().getCacheTtlSeconds() * 1000L;
        cache.put(key, new CacheEntry(result, now + ttlMs));
        if (!result.isSuccess()) {
            return !config.getIntel().isFailOpen();
        }
        return result.shouldBlock(config.getIntel());
    }

    private IntelResult query(InetAddress address) {
        String provider = config.getIntel().getProvider();
        if (provider == null) {
            return IntelResult.failed();
        }
        String normalized = provider.trim().toLowerCase(Locale.ROOT);
        try {
            if (normalized.equals("proxycheck") || normalized.equals("proxycheck.io")) {
                return queryProxyCheck(address);
            }
            if (normalized.equals("ipqualityscore") || normalized.equals("ipqs")) {
                return queryIpQualityScore(address);
            }
        } catch (Exception ex) {
            plugin.getLogger().warning("Intel lookup failed: " + ex.getMessage());
        }
        return IntelResult.failed();
    }

    private IntelResult queryProxyCheck(InetAddress address) throws Exception {
        String ip = address.getHostAddress();
        String key = config.getIntel().getApiKey();
        StringBuilder url = new StringBuilder("https://proxycheck.io/v3/");
        url.append(URLEncoder.encode(ip, "UTF-8"));
        boolean hasQuery = false;

        String apiKey = trimToNull(key);
        if (apiKey != null) {
            hasQuery = appendQueryParam(url, hasQuery, "key", apiKey);
        }
        double days = config.getIntel().getProxycheckDays();
        if (days > 0.0D) {
            hasQuery = appendQueryParam(url, hasQuery, "days", formatDays(days));
        }
        String tag = trimToNull(config.getIntel().getProxycheckTag());
        if (tag != null) {
            hasQuery = appendQueryParam(url, hasQuery, "tag", tag);
        }
        String version = trimToNull(config.getIntel().getProxycheckVersion());
        if (version != null) {
            hasQuery = appendQueryParam(url, hasQuery, "ver", version);
        }
        if (config.getIntel().isProxycheckNode()) {
            hasQuery = appendQueryParam(url, hasQuery, "node", "1");
        }
        if (config.getIntel().isProxycheckShort()) {
            hasQuery = appendQueryParam(url, hasQuery, "short", "1");
        }

        String json = fetch(url.toString());
        String status = findString(PROXYCHECK_STATUS, json);
        if (status == null || !(status.equalsIgnoreCase("ok") || status.equalsIgnoreCase("warning"))) {
            return IntelResult.failed();
        }
        boolean proxy = findBooleanAny(json, PROXYCHECK_PROXY_BOOL, PROXYCHECK_PROXY_STR, PROXYCHECK_ANON_BOOL, PROXYCHECK_ANON_STR);
        boolean vpn = findBooleanAny(json, PROXYCHECK_VPN_BOOL, PROXYCHECK_VPN_STR);
        boolean tor = findBooleanAny(json, PROXYCHECK_TOR_BOOL, PROXYCHECK_TOR_STR);
        boolean hosting = findBooleanAny(json, PROXYCHECK_HOSTING_BOOL, PROXYCHECK_HOSTING_STR);
        String networkType = findString(PROXYCHECK_NETWORK_TYPE, json);
        String typeLower = networkType != null ? networkType.toLowerCase(Locale.ROOT) : "";
        if (!hosting) {
            hosting = typeLower.contains("hosting") || typeLower.contains("datacenter") || typeLower.contains("data center");
        }
        boolean residential = proxy && (typeLower.contains("residential")
                || typeLower.contains("mobile")
                || typeLower.contains("wireless"));
        int risk = findInt(PROXYCHECK_RISK, json);
        String country = findString(PROXYCHECK_COUNTRY, json);
        if (country == null) {
            country = findString(PROXYCHECK_ISO, json);
        }
        return IntelResult.ok(proxy, vpn, tor, hosting, residential, risk, uppercase(country));
    }

    private IntelResult queryIpQualityScore(InetAddress address) throws Exception {
        String key = config.getIntel().getApiKey();
        if (key == null || key.trim().isEmpty()) {
            return IntelResult.failed();
        }
        String ip = address.getHostAddress();
        String url = "https://ipqualityscore.com/api/json/ip/" + URLEncoder.encode(key.trim(), "UTF-8") + "/" + ip;
        String json = fetch(url);
        String success = findString(IPQS_SUCCESS, json);
        if (success == null || !success.equalsIgnoreCase("true")) {
            return IntelResult.failed();
        }
        boolean proxy = findBoolean(IPQS_PROXY, json);
        boolean vpn = findBoolean(IPQS_VPN, json);
        boolean tor = findBoolean(IPQS_TOR, json);
        int fraud = findInt(IPQS_FRAUD, json);
        String country = findString(IPQS_COUNTRY, json);
        String conn = findString(IPQS_CONN, json);
        String connLower = conn != null ? conn.toLowerCase(Locale.ROOT) : "";
        boolean residential = proxy && (connLower.contains("residential") || connLower.contains("mobile"));
        boolean hosting = connLower.contains("data center") || connLower.contains("datacenter") || connLower.contains("hosting");
        return IntelResult.ok(proxy, vpn, tor, hosting, residential, fraud, uppercase(country));
    }

    private String fetch(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(config.getIntel().getTimeoutMs());
        conn.setReadTimeout(config.getIntel().getTimeoutMs());
        conn.setRequestProperty("User-Agent", config.getUpdate().getUserAgent());
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Accept-Encoding", "gzip");
        int code = conn.getResponseCode();
        InputStream input = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
        if (input == null) {
            throw new IllegalStateException("HTTP " + code);
        }
        if ("gzip".equalsIgnoreCase(conn.getContentEncoding())) {
            input = new GZIPInputStream(input);
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        if (code < 200 || code >= 300) {
            throw new IllegalStateException("HTTP " + code);
        }
        return sb.toString();
    }

    private static String findString(Pattern pattern, String json) {
        if (json == null) {
            return null;
        }
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static boolean findBoolean(Pattern pattern, String json) {
        String value = findString(pattern, json);
        if (value == null) {
            return false;
        }
        return "true".equalsIgnoreCase(value);
    }

    private static boolean findBooleanAny(String json, Pattern... patterns) {
        for (Pattern pattern : patterns) {
            String value = findString(pattern, json);
            if (value == null) {
                continue;
            }
            if ("true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value)) {
                return true;
            }
            if ("false".equalsIgnoreCase(value) || "no".equalsIgnoreCase(value)) {
                return false;
            }
        }
        return false;
    }

    private static int findInt(Pattern pattern, String json) {
        String value = findString(pattern, json);
        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static boolean appendQueryParam(StringBuilder url, boolean hasQuery, String key, String value) throws Exception {
        url.append(hasQuery ? "&" : "?");
        url.append(key).append("=").append(URLEncoder.encode(value, "UTF-8"));
        return true;
    }

    private static String formatDays(double days) {
        long rounded = Math.round(days);
        if (Math.abs(days - rounded) < 0.0000001D) {
            return Long.toString(rounded);
        }
        String formatted = String.format(Locale.US, "%.2f", days);
        while (formatted.contains(".") && (formatted.endsWith("0") || formatted.endsWith("."))) {
            formatted = formatted.substring(0, formatted.length() - 1);
        }
        return formatted;
    }

    private static String uppercase(String value) {
        if (value == null) {
            return null;
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private static final class CacheEntry {
        private final IntelResult result;
        private final long expiresAt;

        private CacheEntry(IntelResult result, long expiresAt) {
            this.result = result;
            this.expiresAt = expiresAt;
        }
    }
}
