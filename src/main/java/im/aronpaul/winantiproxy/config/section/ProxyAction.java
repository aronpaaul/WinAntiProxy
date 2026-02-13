package im.aronpaul.winantiproxy.config.section;

public enum ProxyAction {
    HUB,
    KICK;

    public static ProxyAction from(String value) {
        if (value == null) {
            return HUB;
        }
        try {
            return ProxyAction.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return HUB;
        }
    }
}
