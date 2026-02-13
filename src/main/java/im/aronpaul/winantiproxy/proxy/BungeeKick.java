package im.aronpaul.winantiproxy.proxy;

import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

public final class BungeeKick {

    private final JavaPlugin plugin;

    public BungeeKick(JavaPlugin plugin) {
        this.plugin = plugin;
    }

    public void connect(Player player, String server) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeUTF("Connect");
            out.writeUTF(server);
            player.sendPluginMessage(plugin, "BungeeCord", bytes.toByteArray());
        } catch (Exception ignored) {
        }
    }
}
