package im.aronpaul.winantiproxy.config.section;

import java.util.Set;

public final class GeoIpSettings {

    private final boolean enabled;
    private final String mmdbPath;
    private final boolean failOpen;
    private final Set<String> allowCountryCodes;
    private final Set<String> blockCountryCodes;

    public GeoIpSettings(boolean enabled,
                         String mmdbPath,
                         boolean failOpen,
                         Set<String> allowCountryCodes,
                         Set<String> blockCountryCodes) {
        this.enabled = enabled;
        this.mmdbPath = mmdbPath;
        this.failOpen = failOpen;
        this.allowCountryCodes = allowCountryCodes;
        this.blockCountryCodes = blockCountryCodes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getMmdbPath() {
        return mmdbPath;
    }

    public boolean isFailOpen() {
        return failOpen;
    }

    public Set<String> getAllowCountryCodes() {
        return allowCountryCodes;
    }

    public Set<String> getBlockCountryCodes() {
        return blockCountryCodes;
    }
}
