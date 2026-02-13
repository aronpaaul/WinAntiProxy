package im.aronpaul.winantiproxy.config.util;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ConfigParsers {

    private ConfigParsers() {
    }

    public static List<String> safeList(List<String> list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        return new ArrayList<>(list);
    }

    public static Set<InetAddress> parseBypass(List<String> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptySet();
        }
        Set<InetAddress> out = new HashSet<>();
        for (String entry : entries) {
            if (entry == null) {
                continue;
            }
            String value = entry.trim();
            if (value.isEmpty() || value.contains("/")) {
                continue;
            }
            try {
                out.add(InetAddress.getByName(value));
            } catch (Exception ignored) {
            }
        }
        return out;
    }

    public static Set<String> parseCountryCodes(List<String> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> out = new HashSet<>();
        for (String entry : entries) {
            if (entry == null) {
                continue;
            }
            String value = entry.trim().toUpperCase();
            if (value.length() == 2) {
                out.add(value);
            }
        }
        return out;
    }

    public static Set<Long> parseAsnNumbers(List<String> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptySet();
        }
        Set<Long> out = new HashSet<>();
        for (String entry : entries) {
            if (entry == null) {
                continue;
            }
            String value = entry.trim();
            if (value.isEmpty()) {
                continue;
            }
            try {
                long asn = Long.parseLong(value);
                if (asn > 0) {
                    out.add(asn);
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return out;
    }

    public static List<String> parseLowercaseList(List<String> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<>();
        for (String entry : entries) {
            if (entry == null) {
                continue;
            }
            String value = entry.trim().toLowerCase();
            if (!value.isEmpty()) {
                out.add(value);
            }
        }
        return out;
    }
}
