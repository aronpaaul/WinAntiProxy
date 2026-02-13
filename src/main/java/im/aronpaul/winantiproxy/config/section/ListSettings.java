package im.aronpaul.winantiproxy.config.section;

import java.net.InetAddress;
import java.util.List;
import java.util.Set;

public final class ListSettings {

    private final List<String> sources;
    private final List<String> inline;
    private final Set<InetAddress> bypass;

    public ListSettings(List<String> sources, List<String> inline, Set<InetAddress> bypass) {
        this.sources = sources;
        this.inline = inline;
        this.bypass = bypass;
    }

    public List<String> getSources() {
        return sources;
    }

    public List<String> getInline() {
        return inline;
    }

    public boolean isBypassed(InetAddress address) {
        return bypass.contains(address);
    }
}
