package im.aronpaul.winantiproxy.detect;

import java.net.InetAddress;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IpParser {

    private static final Pattern JSON_HOST = Pattern.compile("\"host\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_IP = Pattern.compile("\"ip\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_ADDRESS = Pattern.compile("\"address\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?:/\\d{1,2})?\\b");
    private static final Pattern IPV6_BRACKET = Pattern.compile("\\[([0-9a-fA-F:]+)](?:/(\\d{1,3}))?");
    private static final Pattern IPV6_PATTERN = Pattern.compile("\\b[0-9a-fA-F:]{2,}\\b(?:/\\d{1,3})?");

    public static ParsedIp parse(String raw) {
        if (raw == null) {
            return null;
        }
        String line = raw.trim();
        if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) {
            return null;
        }
        String jsonValue = extractJsonValue(line);
        if (jsonValue != null) {
            ParsedIp parsed = parseCandidate(jsonValue);
            if (parsed != null) {
                return parsed;
            }
        }
        if (!line.startsWith("{")) {
            ParsedIp parsed = parseCandidate(line);
            if (parsed != null) {
                return parsed;
            }
        }
        for (String token : tokenize(line)) {
            ParsedIp parsed = parseCandidate(token);
            if (parsed != null) {
                return parsed;
            }
        }
        ParsedIp parsed = parseFromRegex(line);
        if (parsed != null) {
            return parsed;
        }
        return null;
    }

    private static String extractJsonValue(String line) {
        String value = match(JSON_HOST, line);
        if (value != null) {
            return value;
        }
        value = match(JSON_IP, line);
        if (value != null) {
            return value;
        }
        return match(JSON_ADDRESS, line);
    }

    private static String match(Pattern pattern, String line) {
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static String[] tokenize(String line) {
        return line.split("[\\s,;|]+");
    }

    private static ParsedIp parseFromRegex(String line) {
        Matcher m4 = IPV4_PATTERN.matcher(line);
        while (m4.find()) {
            ParsedIp parsed = parseCandidate(m4.group());
            if (parsed != null) {
                return parsed;
            }
        }
        Matcher m6b = IPV6_BRACKET.matcher(line);
        while (m6b.find()) {
            String host = m6b.group(1);
            String prefix = m6b.group(2);
            String candidate = prefix == null ? host : host + "/" + prefix;
            ParsedIp parsed = parseCandidate(candidate);
            if (parsed != null) {
                return parsed;
            }
        }
        Matcher m6 = IPV6_PATTERN.matcher(line);
        while (m6.find()) {
            String candidate = m6.group();
            if (!candidate.contains(":")) {
                continue;
            }
            ParsedIp parsed = parseCandidate(candidate);
            if (parsed != null) {
                return parsed;
            }
        }
        return null;
    }

    private static ParsedIp parseCandidate(String raw) {
        if (raw == null) {
            return null;
        }
        String line = raw.trim();
        if (line.isEmpty()) {
            return null;
        }
        int hash = line.indexOf('#');
        if (hash > -1) {
            line = line.substring(0, hash).trim();
        }
        if (line.isEmpty()) {
            return null;
        }
        line = stripProtocol(line);
        if (line.contains("@")) {
            line = line.substring(line.lastIndexOf('@') + 1);
        }
        String host = line;
        String prefixPart = null;
        int slash = line.lastIndexOf('/');
        if (slash > -1) {
            String after = line.substring(slash + 1);
            if (isDigits(after)) {
                prefixPart = after;
                host = line.substring(0, slash);
            } else {
                host = line.substring(0, slash);
            }
        }
        host = stripBrackets(host);
        if (host.indexOf(':') == host.lastIndexOf(':') && host.contains(".")) {
            int idx = host.indexOf(':');
            if (idx > -1) {
                host = host.substring(0, idx);
            }
        }
        if (host.isEmpty()) {
            return null;
        }
        InetAddress address = parseNumeric(host);
        if (address == null || !isPublic(address)) {
            return null;
        }
        if (prefixPart != null) {
            int max = address.getAddress().length == 4 ? 32 : 128;
            int prefix = Integer.parseInt(prefixPart);
            if (prefix < 0 || prefix > max) {
                return null;
            }
            return ParsedIp.cidr(CidrMatcher.from(address, prefix));
        }
        return ParsedIp.exact(address);
    }

    private static String stripProtocol(String value) {
        String lower = value.toLowerCase();
        String[] prefixes = {"http://", "https://", "socks4://", "socks5://", "socks://", "tcp://", "udp://"};
        for (String prefix : prefixes) {
            if (lower.startsWith(prefix)) {
                return value.substring(prefix.length());
            }
        }
        return value;
    }

    private static String stripBrackets(String host) {
        if (host.startsWith("[") && host.contains("]")) {
            int end = host.indexOf(']');
            return host.substring(1, end);
        }
        return host;
    }

    private static InetAddress parseNumeric(String host) {
        byte[] ipv4 = parseIpv4(host);
        if (ipv4 != null) {
            try {
                return InetAddress.getByAddress(ipv4);
            } catch (Exception ignored) {
                return null;
            }
        }
        if (isIpv6Literal(host)) {
            try {
                return InetAddress.getByName(host);
            } catch (Exception ignored) {
                return null;
            }
        }
        return null;
    }

    private static byte[] parseIpv4(String host) {
        if (!isIpv4Literal(host)) {
            return null;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            int value;
            try {
                value = Integer.parseInt(parts[i]);
            } catch (NumberFormatException ex) {
                return null;
            }
            if (value < 0 || value > 255) {
                return null;
            }
            out[i] = (byte) value;
        }
        return out;
    }

    private static boolean isIpv4Literal(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == '.') {
                continue;
            }
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return host.contains(".");
    }

    private static boolean isIpv6Literal(String host) {
        if (host == null || host.isEmpty() || !host.contains(":")) {
            return false;
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == ':') {
                continue;
            }
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                continue;
            }
            return false;
        }
        return true;
    }

    private static boolean isPublic(InetAddress address) {
        return !(address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress());
    }

    private static boolean isDigits(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    public static final class ParsedIp {
        private final InetAddress exact;
        private final CidrMatcher cidr;

        private ParsedIp(InetAddress exact, CidrMatcher cidr) {
            this.exact = exact;
            this.cidr = cidr;
        }

        public static ParsedIp exact(InetAddress exact) {
            return new ParsedIp(exact, null);
        }

        public static ParsedIp cidr(CidrMatcher cidr) {
            return new ParsedIp(null, cidr);
        }

        public boolean isExact() {
            return exact != null;
        }

        public InetAddress getExact() {
            return exact;
        }

        public CidrMatcher getCidr() {
            return cidr;
        }
    }
}
