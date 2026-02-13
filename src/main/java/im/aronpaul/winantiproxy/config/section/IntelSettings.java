package im.aronpaul.winantiproxy.config.section;

import java.util.Set;

public final class IntelSettings {

    private final boolean enabled;
    private final String provider;
    private final String apiKey;
    private final int timeoutMs;
    private final int cacheTtlSeconds;
    private final boolean checkWhenListMiss;
    private final boolean failOpen;
    private final boolean blockProxy;
    private final boolean blockVpn;
    private final boolean blockTor;
    private final boolean blockHosting;
    private final boolean blockResidentialProxy;
    private final int minFraudScore;
    private final Set<String> allowCountryCodes;
    private final Set<String> blockCountryCodes;

    public IntelSettings(boolean enabled,
                         String provider,
                         String apiKey,
                         int timeoutMs,
                         int cacheTtlSeconds,
                         boolean checkWhenListMiss,
                         boolean failOpen,
                         boolean blockProxy,
                         boolean blockVpn,
                         boolean blockTor,
                         boolean blockHosting,
                         boolean blockResidentialProxy,
                         int minFraudScore,
                         Set<String> allowCountryCodes,
                         Set<String> blockCountryCodes) {
        this.enabled = enabled;
        this.provider = provider;
        this.apiKey = apiKey;
        this.timeoutMs = timeoutMs;
        this.cacheTtlSeconds = cacheTtlSeconds;
        this.checkWhenListMiss = checkWhenListMiss;
        this.failOpen = failOpen;
        this.blockProxy = blockProxy;
        this.blockVpn = blockVpn;
        this.blockTor = blockTor;
        this.blockHosting = blockHosting;
        this.blockResidentialProxy = blockResidentialProxy;
        this.minFraudScore = minFraudScore;
        this.allowCountryCodes = allowCountryCodes;
        this.blockCountryCodes = blockCountryCodes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getProvider() {
        return provider;
    }

    public String getApiKey() {
        return apiKey;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public int getCacheTtlSeconds() {
        return cacheTtlSeconds;
    }

    public boolean isCheckWhenListMiss() {
        return checkWhenListMiss;
    }

    public boolean isFailOpen() {
        return failOpen;
    }

    public boolean isBlockProxy() {
        return blockProxy;
    }

    public boolean isBlockVpn() {
        return blockVpn;
    }

    public boolean isBlockTor() {
        return blockTor;
    }

    public boolean isBlockHosting() {
        return blockHosting;
    }

    public boolean isBlockResidentialProxy() {
        return blockResidentialProxy;
    }

    public int getMinFraudScore() {
        return minFraudScore;
    }

    public Set<String> getAllowCountryCodes() {
        return allowCountryCodes;
    }

    public Set<String> getBlockCountryCodes() {
        return blockCountryCodes;
    }
}
