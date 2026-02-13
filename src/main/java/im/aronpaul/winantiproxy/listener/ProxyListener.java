package im.aronpaul.winantiproxy.listener;

import im.aronpaul.winantiproxy.WinAntiProxy;
import im.aronpaul.winantiproxy.config.Settings;
import im.aronpaul.winantiproxy.config.section.ProxyAction;
import im.aronpaul.winantiproxy.detect.ProxyListService;
import im.aronpaul.winantiproxy.detect.geo.AsnService;
import im.aronpaul.winantiproxy.detect.geo.GeoIpService;
import im.aronpaul.winantiproxy.detect.intel.IntelService;
import im.aronpaul.winantiproxy.proxy.BungeeKick;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;

import java.net.InetAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class ProxyListener implements Listener {

    private final WinAntiProxy plugin;
    private final Settings config;
    private final ProxyListService listService;
    private final GeoIpService geoIpService;
    private final AsnService asnService;
    private final IntelService intelService;
    private final BungeeKick connector;
    private final Map<UUID, Boolean> flagged = new ConcurrentHashMap<>();

    public ProxyListener(WinAntiProxy plugin, Settings config, ProxyListService listService, GeoIpService geoIpService, AsnService asnService, IntelService intelService, BungeeKick connector) {
        this.plugin = plugin;
        this.config = config;
        this.listService = listService;
        this.geoIpService = geoIpService;
        this.asnService = asnService;
        this.intelService = intelService;
        this.connector = connector;
    }

    @EventHandler
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!config.getProxy().isPreloginCheck()) {
            return;
        }
        InetAddress address = event.getAddress();
        boolean listMatch = listService.isProxy(address);
        boolean geoBlock = geoIpService != null && geoIpService.isBlocked(address);
        boolean asnBlock = asnService != null && asnService.isBlocked(address);
        if (listMatch || geoBlock || asnBlock) {
            handleDetected(event);
            return;
        }
        if (shouldCheckIntel(listMatch)) {
            if (intelService.isBlocked(address)) {
                handleDetected(event);
            }
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        ProxyAction action = config.getProxy().getAction();
        if (action == ProxyAction.HUB) {
            boolean proxy = flagged.remove(player.getUniqueId()) != null;
            if (!proxy && config.getProxy().isJoinCheck()) {
                InetAddress address = player.getAddress() != null ? player.getAddress().getAddress() : null;
                boolean listMatch = listService.isProxy(address);
                boolean geoBlock = geoIpService != null && geoIpService.isBlocked(address);
                boolean asnBlock = asnService != null && asnService.isBlocked(address);
                proxy = listMatch || geoBlock || asnBlock;
                if (!proxy && shouldCheckIntel(listMatch)) {
                    checkIntelAsync(player, address, action);
                }
            }
            if (proxy) {
                handleHub(player);
            }
            return;
        }
        if (action == ProxyAction.KICK && config.getProxy().isJoinCheck() && !config.getProxy().isPreloginCheck()) {
            InetAddress address = player.getAddress() != null ? player.getAddress().getAddress() : null;
            boolean listMatch = listService.isProxy(address);
            boolean geoBlock = geoIpService != null && geoIpService.isBlocked(address);
            boolean asnBlock = asnService != null && asnService.isBlocked(address);
            if (listMatch || geoBlock || asnBlock) {
                player.kickPlayer(config.getProxy().getMessage());
                return;
            }
            if (shouldCheckIntel(listMatch)) {
                checkIntelAsync(player, address, action);
            }
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        flagged.remove(event.getPlayer().getUniqueId());
    }

    private void handleHub(Player player) {
        if (config.getProxy().isSendMessageBeforeTransfer() && !config.getProxy().getMessage().isEmpty()) {
            player.sendMessage(config.getProxy().getMessage());
        }
        plugin.getServer().getScheduler().runTask(plugin, () -> connector.connect(player, config.getProxy().getHubServer()));
        int fallback = config.getProxy().getHubFallbackKickTicks();
        if (fallback > 0) {
            plugin.getServer().getScheduler().runTaskLater(plugin, () -> {
                if (player.isOnline()) {
                    player.kickPlayer(config.getProxy().getMessage());
                }
            }, fallback);
        }
    }

    private void handleDetected(AsyncPlayerPreLoginEvent event) {
        if (config.getProxy().getAction() == ProxyAction.KICK) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, config.getProxy().getMessage());
            return;
        }
        if (config.getProxy().getAction() == ProxyAction.HUB) {
            flagged.put(event.getUniqueId(), Boolean.TRUE);
        }
    }

    private boolean shouldCheckIntel(boolean listMatch) {
        if (intelService == null || !config.getIntel().isEnabled()) {
            return false;
        }
        return !listMatch || !config.getIntel().isCheckWhenListMiss();
    }

    private void checkIntelAsync(Player player, InetAddress address, ProxyAction action) {
        if (address == null) {
            return;
        }
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            if (!intelService.isBlocked(address)) {
                return;
            }
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                if (!player.isOnline()) {
                    return;
                }
                if (action == ProxyAction.HUB) {
                    handleHub(player);
                } else if (action == ProxyAction.KICK) {
                    player.kickPlayer(config.getProxy().getMessage());
                }
            });
        });
    }
}
