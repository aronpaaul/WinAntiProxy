package im.aronpaul.winantiproxy;

import im.aronpaul.winantiproxy.config.Settings;
import im.aronpaul.winantiproxy.detect.ProxyListService;
import im.aronpaul.winantiproxy.detect.geo.AsnService;
import im.aronpaul.winantiproxy.detect.geo.GeoIpService;
import im.aronpaul.winantiproxy.detect.intel.IntelService;
import im.aronpaul.winantiproxy.listener.ProxyListener;
import im.aronpaul.winantiproxy.proxy.BungeeKick;
import org.bukkit.plugin.java.JavaPlugin;

public final class WinAntiProxy extends JavaPlugin {

    private Settings settings;
    private ProxyListService proxyListService;
    private IntelService intelService;
    private GeoIpService geoIpService;
    private AsnService asnService;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        settings = Settings.load(this);
        proxyListService = new ProxyListService(this, settings);
        intelService = new IntelService(this, settings);
        geoIpService = new GeoIpService(this, settings);
        asnService = new AsnService(this, settings);
        getServer().getMessenger().registerOutgoingPluginChannel(this, "BungeeCord");
        getServer().getPluginManager().registerEvents(
                new ProxyListener(this, settings, proxyListService, geoIpService, asnService, intelService, new BungeeKick(this)),
                this
        );
        proxyListService.refreshAsync();
        if (settings.getUpdate().isEnabled()) {
            long intervalTicks = settings.getUpdate().getIntervalSeconds() * 20L;
            getServer().getScheduler().runTaskTimerAsynchronously(this, proxyListService::refresh, intervalTicks, intervalTicks);
        }
    }

    @Override
    public void onDisable() {
        getServer().getScheduler().cancelTasks(this);
        if (geoIpService != null) {
            geoIpService.close();
        }
        if (asnService != null) {
            asnService.close();
        }
    }
}
