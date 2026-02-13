package im.aronpaul.winantiproxy.config.section;

public final class UpdateSettings {

    private final boolean enabled;
    private final int intervalSeconds;
    private final int requestTimeoutMs;
    private final String userAgent;

    public UpdateSettings(boolean enabled, int intervalSeconds, int requestTimeoutMs, String userAgent) {
        this.enabled = enabled;
        this.intervalSeconds = intervalSeconds;
        this.requestTimeoutMs = requestTimeoutMs;
        this.userAgent = userAgent;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getIntervalSeconds() {
        return intervalSeconds;
    }

    public int getRequestTimeoutMs() {
        return requestTimeoutMs;
    }

    public String getUserAgent() {
        return userAgent;
    }
}
