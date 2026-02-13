package im.aronpaul.winantiproxy.detect;

import java.net.InetAddress;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public final class IpStore {

    private final Set<InetAddress> exact;
    private final List<CidrMatcher> cidrs;

    public IpStore(Set<InetAddress> exact, List<CidrMatcher> cidrs) {
        this.exact = exact;
        this.cidrs = cidrs;
    }

    public boolean matches(InetAddress address) {
        if (exact.contains(address)) {
            return true;
        }
        for (CidrMatcher cidr : cidrs) {
            if (cidr.matches(address)) {
                return true;
            }
        }
        return false;
    }

    public int exactCount() {
        return exact.size();
    }

    public int cidrCount() {
        return cidrs.size();
    }

    public static IpStore empty() {
        return new IpStore(Collections.emptySet(), Collections.emptyList());
    }
}
