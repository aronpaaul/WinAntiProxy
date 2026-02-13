package im.aronpaul.winantiproxy.config.section;

import java.util.List;
import java.util.Set;

public final class AsnSettings {

    private final boolean enabled;
    private final String mmdbPath;
    private final boolean failOpen;
    private final Set<Long> blockNumbers;
    private final List<String> blockOrgContains;

    public AsnSettings(boolean enabled,
                       String mmdbPath,
                       boolean failOpen,
                       Set<Long> blockNumbers,
                       List<String> blockOrgContains) {
        this.enabled = enabled;
        this.mmdbPath = mmdbPath;
        this.failOpen = failOpen;
        this.blockNumbers = blockNumbers;
        this.blockOrgContains = blockOrgContains;
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

    public Set<Long> getBlockNumbers() {
        return blockNumbers;
    }

    public List<String> getBlockOrgContains() {
        return blockOrgContains;
    }
}
