package im.aronpaul.winantiproxy.config;

import im.aronpaul.winantiproxy.config.section.AsnSettings;
import im.aronpaul.winantiproxy.config.section.GeoIpSettings;
import im.aronpaul.winantiproxy.config.section.IntelSettings;
import im.aronpaul.winantiproxy.config.section.ListSettings;
import im.aronpaul.winantiproxy.config.section.ProxyAction;
import im.aronpaul.winantiproxy.config.section.ProxySettings;
import im.aronpaul.winantiproxy.config.section.UpdateSettings;
import im.aronpaul.winantiproxy.config.util.ConfigParsers;
import org.bukkit.ChatColor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.net.InetAddress;
import java.util.List;
import java.util.Set;

public final class Settings {

    private final ProxySettings proxy;
    private final ListSettings lists;
    private final UpdateSettings update;
    private final IntelSettings intel;
    private final GeoIpSettings geoip;
    private final AsnSettings asn;

    private Settings(ProxySettings proxy,
                     ListSettings lists,
                     UpdateSettings update,
                     IntelSettings intel,
                     GeoIpSettings geoip,
                     AsnSettings asn) {
        this.proxy = proxy;
        this.lists = lists;
        this.update = update;
        this.intel = intel;
        this.geoip = geoip;
        this.asn = asn;
    }

    public static Settings load(JavaPlugin plugin) {
        FileConfiguration cfg = plugin.getConfig();
        ProxyAction action = ProxyAction.from(cfg.getString("proxy.action", "HUB"));
        String hubServer = cfg.getString("proxy.hub-server", "hub");
        String rawMessage = cfg.getString("proxy.message",
                "&cОтключите VPN или прокси и попробуйте зайти еще раз");
        String message = ChatColor.translateAlternateColorCodes('&', rawMessage);
        boolean sendMessageBeforeTransfer = cfg.getBoolean("proxy.send-message-before-transfer", true);
        boolean preloginCheck = cfg.getBoolean("proxy.prelogin-check", true);
        boolean joinCheck = cfg.getBoolean("proxy.join-check", true);
        int hubFallbackKickTicks = Math.max(0, cfg.getInt("proxy.hub-fallback-kick-ticks", 0));
        ProxySettings proxy = new ProxySettings(action, hubServer, message, sendMessageBeforeTransfer, preloginCheck,
                joinCheck, hubFallbackKickTicks);

        List<String> sources = ConfigParsers.safeList(cfg.getStringList("lists.sources"));
        List<String> inline = ConfigParsers.safeList(cfg.getStringList("lists.inline"));
        Set<InetAddress> bypass = ConfigParsers.parseBypass(cfg.getStringList("lists.bypass-ips"));
        ListSettings lists = new ListSettings(sources, inline, bypass);

        boolean updateEnabled = cfg.getBoolean("update.enabled", true);
        int updateIntervalSeconds = Math.max(60, cfg.getInt("update.interval-seconds", 1800));
        int timeoutMs = Math.max(1000, cfg.getInt("update.request-timeout-ms", 8000));
        String userAgent = cfg.getString("update.user-agent", "WinAntiProxy/1.0.1");
        UpdateSettings update = new UpdateSettings(updateEnabled, updateIntervalSeconds, timeoutMs, userAgent);

        boolean intelEnabled = cfg.getBoolean("intel.enabled", false);
        String intelProvider = cfg.getString("intel.provider", "ipqualityscore");
        String intelApiKey = cfg.getString("intel.api-key", "");
        int intelTimeoutMs = Math.max(1000, cfg.getInt("intel.timeout-ms", 4000));
        int intelCacheTtlSeconds = Math.max(60, cfg.getInt("intel.cache-ttl-seconds", 1800));
        boolean intelCheckWhenListMiss = cfg.getBoolean("intel.check-when-list-miss", true);
        boolean intelFailOpen = cfg.getBoolean("intel.fail-open", true);
        boolean blockProxy = cfg.getBoolean("intel.block-proxy", true);
        boolean blockVpn = cfg.getBoolean("intel.block-vpn", true);
        boolean blockTor = cfg.getBoolean("intel.block-tor", true);
        boolean blockHosting = cfg.getBoolean("intel.block-hosting", false);
        boolean blockResidentialProxy = cfg.getBoolean("intel.block-residential-proxy", true);
        int minFraudScore = Math.max(0, cfg.getInt("intel.min-fraud-score", 0));
        Set<String> allowCountryCodes = ConfigParsers.parseCountryCodes(cfg.getStringList("intel.allow-country-codes"));
        Set<String> blockCountryCodes = ConfigParsers.parseCountryCodes(cfg.getStringList("intel.block-country-codes"));
        double proxycheckDays = cfg.getDouble("intel.proxycheck.days", 7.0D);
        if (proxycheckDays < 0.01D) {
            proxycheckDays = 0.0D;
        } else if (proxycheckDays > 60.0D) {
            proxycheckDays = 60.0D;
        }
        String proxycheckTag = cfg.getString("intel.proxycheck.tag", "");
        String proxycheckVersion = cfg.getString("intel.proxycheck.version", "");
        boolean proxycheckNode = cfg.getBoolean("intel.proxycheck.include-node", false);
        boolean proxycheckShort = cfg.getBoolean("intel.proxycheck.short-response", false);
        IntelSettings intel = new IntelSettings(intelEnabled, intelProvider, intelApiKey, intelTimeoutMs,
                intelCacheTtlSeconds, intelCheckWhenListMiss, intelFailOpen, blockProxy, blockVpn, blockTor,
                blockHosting, blockResidentialProxy, minFraudScore, allowCountryCodes, blockCountryCodes,
                proxycheckDays, proxycheckTag, proxycheckVersion, proxycheckNode, proxycheckShort);

        boolean geoipEnabled = cfg.getBoolean("geoip.enabled", false);
        String geoipMmdbPath = cfg.getString("geoip.mmdb-path", "GeoLite2-Country.mmdb");
        boolean geoipFailOpen = cfg.getBoolean("geoip.fail-open", false);
        Set<String> geoipAllowCountryCodes = ConfigParsers.parseCountryCodes(cfg.getStringList("geoip.allow-country-codes"));
        Set<String> geoipBlockCountryCodes = ConfigParsers.parseCountryCodes(cfg.getStringList("geoip.block-country-codes"));
        GeoIpSettings geoip = new GeoIpSettings(geoipEnabled, geoipMmdbPath, geoipFailOpen,
                geoipAllowCountryCodes, geoipBlockCountryCodes);

        boolean asnEnabled = cfg.getBoolean("asn.enabled", false);
        String asnMmdbPath = cfg.getString("asn.mmdb-path", "GeoLite2-ASN.mmdb");
        boolean asnFailOpen = cfg.getBoolean("asn.fail-open", true);
        Set<Long> asnBlockNumbers = ConfigParsers.parseAsnNumbers(cfg.getStringList("asn.block-asn"));
        List<String> asnBlockOrgContains = ConfigParsers.parseLowercaseList(cfg.getStringList("asn.block-org-contains"));
        AsnSettings asn = new AsnSettings(asnEnabled, asnMmdbPath, asnFailOpen, asnBlockNumbers, asnBlockOrgContains);

        return new Settings(proxy, lists, update, intel, geoip, asn);
    }

    public ProxySettings getProxy() {
        return proxy;
    }

    public ListSettings getLists() {
        return lists;
    }

    public UpdateSettings getUpdate() {
        return update;
    }

    public IntelSettings getIntel() {
        return intel;
    }

    public GeoIpSettings getGeoip() {
        return geoip;
    }

    public AsnSettings getAsn() {
        return asn;
    }
}
