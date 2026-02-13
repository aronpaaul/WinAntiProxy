package im.aronpaul.winantiproxy.detect.geo;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.CountryResponse;
import im.aronpaul.winantiproxy.config.Settings;
import im.aronpaul.winantiproxy.config.section.GeoIpSettings;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.net.InetAddress;
import java.util.Locale;

public final class GeoIpService {

    private final JavaPlugin plugin;
    private final Settings config;
    private final GeoIpSettings geoip;
    private DatabaseReader reader;
    private boolean enabled;

    public GeoIpService(JavaPlugin plugin, Settings config) {
        this.plugin = plugin;
        this.config = config;
        this.geoip = config.getGeoip();
        this.enabled = geoip.isEnabled();
        if (enabled) {
            load();
        }
    }

    public boolean isBlocked(InetAddress address) {
        if (!enabled || reader == null || address == null) {
            return false;
        }
        String code = lookupCountry(address);
        if (code == null) {
            if (!geoip.getAllowCountryCodes().isEmpty()) {
                return !geoip.isFailOpen();
            }
            return false;
        }
        if (!geoip.getAllowCountryCodes().isEmpty()) {
            return !geoip.getAllowCountryCodes().contains(code);
        }
        return geoip.getBlockCountryCodes().contains(code);
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
        String path = geoip.getMmdbPath();
        if (path == null || path.trim().isEmpty()) {
            enabled = false;
            plugin.getLogger().warning("GeoIP disabled: mmdb-path is empty.");
            return;
        }
        File file = new File(path);
        if (!file.isAbsolute()) {
            file = new File(plugin.getDataFolder(), path);
        }
        if (!file.exists()) {
            enabled = false;
            plugin.getLogger().warning("GeoIP disabled: mmdb file not found at " + file.getAbsolutePath());
            return;
        }
        try {
            reader = new DatabaseReader.Builder(file).build();
        } catch (Exception ex) {
            enabled = false;
            plugin.getLogger().warning("GeoIP disabled: " + ex.getMessage());
        }
    }

    private String lookupCountry(InetAddress address) {
        try {
            CountryResponse response = reader.country(address);
            if (response == null || response.getCountry() == null) {
                return null;
            }
            String code = response.getCountry().getIsoCode();
            if (code == null) {
                return null;
            }
            return code.trim().toUpperCase(Locale.ROOT);
        } catch (AddressNotFoundException ex) {
            return null;
        } catch (Exception ex) {
            return null;
        }
    }
}
