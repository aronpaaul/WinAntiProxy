package im.aronpaul.winantiproxy.config.section;

public final class ProxySettings {

    private final ProxyAction action;
    private final String hubServer;
    private final String message;
    private final boolean sendMessageBeforeTransfer;
    private final boolean preloginCheck;
    private final boolean joinCheck;
    private final int hubFallbackKickTicks;

    public ProxySettings(ProxyAction action,
                         String hubServer,
                         String message,
                         boolean sendMessageBeforeTransfer,
                         boolean preloginCheck,
                         boolean joinCheck,
                         int hubFallbackKickTicks) {
        this.action = action;
        this.hubServer = hubServer;
        this.message = message;
        this.sendMessageBeforeTransfer = sendMessageBeforeTransfer;
        this.preloginCheck = preloginCheck;
        this.joinCheck = joinCheck;
        this.hubFallbackKickTicks = hubFallbackKickTicks;
    }

    public ProxyAction getAction() {
        return action;
    }

    public String getHubServer() {
        return hubServer;
    }

    public String getMessage() {
        return message;
    }

    public boolean isSendMessageBeforeTransfer() {
        return sendMessageBeforeTransfer;
    }

    public boolean isPreloginCheck() {
        return preloginCheck;
    }

    public boolean isJoinCheck() {
        return joinCheck;
    }

    public int getHubFallbackKickTicks() {
        return hubFallbackKickTicks;
    }
}
