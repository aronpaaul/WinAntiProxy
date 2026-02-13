package im.aronpaul.winantiproxy.detect;

import im.aronpaul.winantiproxy.config.Settings;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPInputStream;

public final class ProxyListService {

    private final JavaPlugin plugin;
    private final Settings config;
    private final AtomicReference<IpStore> store = new AtomicReference<>(IpStore.empty());

    public ProxyListService(JavaPlugin plugin, Settings config) {
        this.plugin = plugin;
        this.config = config;
    }

    public void refreshAsync() {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, this::refresh);
    }

    public void refresh() {
        List<String> sources = config.getLists().getSources();
        List<String> inline = config.getLists().getInline();
        Set<InetAddress> exact = new HashSet<>();
        List<CidrMatcher> cidrs = new ArrayList<>();
        int loadedSources = 0;
        int failedSources = 0;

        for (String source : sources) {
            if (source == null || source.trim().isEmpty()) {
                continue;
            }
            try {
                loadedSources++;
                parseSource(source.trim(), exact, cidrs);
            } catch (Exception ex) {
                failedSources++;
                plugin.getLogger().warning("Ошибка при загрузке списка прокси: " + source + " (" + ex.getMessage() + ")");
            }
        }

        if (inline != null && !inline.isEmpty()) {
            parseLines(inline, exact, cidrs);
        }

        store.set(new IpStore(exact, cidrs));
        plugin.getLogger().info("Список публичных прокси загружен. Точные IP адреса: " + exact.size() + ", CIDR: " + cidrs.size()
                + ", количество источников: " + loadedSources + ", ошибочно: " + failedSources);
    }

    public boolean isProxy(InetAddress address) {
        if (address == null) {
            return false;
        }
        if (config.getLists().isBypassed(address)) {
            return false;
        }
        return store.get().matches(address);
    }

    private void parseLines(List<String> lines, Set<InetAddress> exact, List<CidrMatcher> cidrs) {
        for (String line : lines) {
            IpParser.ParsedIp parsed = IpParser.parse(line);
            if (parsed == null) {
                continue;
            }
            if (parsed.isExact()) {
                exact.add(parsed.getExact());
            } else if (parsed.getCidr() != null) {
                cidrs.add(parsed.getCidr());
            }
        }
    }

    private void parseSource(String source, Set<InetAddress> exact, List<CidrMatcher> cidrs) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(source).openConnection();
        conn.setConnectTimeout(config.getUpdate().getRequestTimeoutMs());
        conn.setReadTimeout(config.getUpdate().getRequestTimeoutMs());
        conn.setRequestProperty("User-Agent", config.getUpdate().getUserAgent());
        conn.setRequestProperty("Accept", "text/plain");
        conn.setRequestProperty("Accept-Encoding", "gzip");
        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            throw new IllegalStateException("HTTP " + code);
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(openStream(conn, source), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                IpParser.ParsedIp parsed = IpParser.parse(line);
                if (parsed == null) {
                    continue;
                }
                if (parsed.isExact()) {
                    exact.add(parsed.getExact());
                } else if (parsed.getCidr() != null) {
                    cidrs.add(parsed.getCidr());
                }
            }
        }
    }

    private InputStream openStream(HttpURLConnection conn, String source) throws Exception {
        InputStream input = conn.getInputStream();
        String encoding = conn.getContentEncoding();
        if ("gzip".equalsIgnoreCase(encoding) || source.endsWith(".gz")) {
            return new GZIPInputStream(input);
        }
        return input;
    }
}
