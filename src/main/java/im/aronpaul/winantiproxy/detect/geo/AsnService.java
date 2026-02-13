package im.aronpaul.winantiproxy.detect.geo;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.AsnResponse;
import im.aronpaul.winantiproxy.config.Settings;
import im.aronpaul.winantiproxy.config.section.AsnSettings;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.net.InetAddress;
import java.util.List;
import java.util.Locale;

public final class AsnService {

    private final JavaPlugin plugin;
    private final Settings config;
    private final AsnSettings asn;
    private DatabaseReader reader;
    private boolean enabled;

    public AsnService(JavaPlugin plugin, Settings config) {
        this.plugin = plugin;
        this.config = config;
        this.asn = config.getAsn();
        this.enabled = asn.isEnabled();
        if (enabled) {
            load();
        }
    }

    public boolean isBlocked(InetAddress address) {
        if (!enabled || reader == null || address == null) {
            return false;
        }
        AsnInfo info = lookup(address);
        if (info == null) {
            return !asn.isFailOpen();
        }
        if (asn.getBlockNumbers().contains(info.asn)) {
            return true;
        }
        List<String> orgContains = asn.getBlockOrgContains();
        if (!orgContains.isEmpty() && info.org != null) {
            String orgLower = info.org.toLowerCase(Locale.ROOT);
            for (String token : orgContains) {
                if (orgLower.contains(token)) {
                    return true;
                }
            }
        }
        return false;
    }

    public void close() {
        try {
            if (reader != null) {
                reader.close();
            }
        } catch (Exception ignored) {
        }
    }

    private void load() {
        String path = asn.getMmdbPath();
        if (path == null || path.trim().isEmpty()) {
            enabled = false;
            plugin.getLogger().warning("ASN disabled: mmdb-path is empty.");
            return;
        }
        File file = new File(path);
        if (!file.isAbsolute()) {
            file = new File(plugin.getDataFolder(), path);
        }
        if (!file.exists()) {
            enabled = false;
            plugin.getLogger().warning("ASN disabled: mmdb file not found at " + file.getAbsolutePath());
            return;
        }
        try {
            reader = new DatabaseReader.Builder(file).build();
        } catch (Exception ex) {
            enabled = false;
            plugin.getLogger().warning("ASN disabled: " + ex.getMessage());
        }
    }

    private AsnInfo lookup(InetAddress address) {
        try {
            AsnResponse response = reader.asn(address);
            if (response == null) {
                return null;
            }
            Long asn = response.getAutonomousSystemNumber();
            String org = response.getAutonomousSystemOrganization();
            if (asn == null && org == null) {
                return null;
            }
            return new AsnInfo(asn == null ? -1 : asn, org);
        } catch (AddressNotFoundException ex) {
            return null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static final class AsnInfo {
        private final long asn;
        private final String org;

        private AsnInfo(long asn, String org) {
            this.asn = asn;
            this.org = org;
        }
    }
}
