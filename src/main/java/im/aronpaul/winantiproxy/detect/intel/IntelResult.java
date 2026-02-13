package im.aronpaul.winantiproxy.detect.intel;

import im.aronpaul.winantiproxy.config.section.IntelSettings;

public final class IntelResult {

    private final boolean success;
    private final boolean proxy;
    private final boolean vpn;
    private final boolean tor;
    private final boolean hosting;
    private final boolean residentialProxy;
    private final int fraudScore;
    private final String countryCode;

    private IntelResult(boolean success,
                        boolean proxy,
                        boolean vpn,
                        boolean tor,
                        boolean hosting,
                        boolean residentialProxy,
                        int fraudScore,
                        String countryCode) {
        this.success = success;
        this.proxy = proxy;
        this.vpn = vpn;
        this.tor = tor;
        this.hosting = hosting;
        this.residentialProxy = residentialProxy;
        this.fraudScore = fraudScore;
        this.countryCode = countryCode;
    }

    public static IntelResult ok(boolean proxy,
                                 boolean vpn,
                                 boolean tor,
                                 boolean hosting,
                                 boolean residentialProxy,
                                 int fraudScore,
                                 String countryCode) {
        return new IntelResult(true, proxy, vpn, tor, hosting, residentialProxy, fraudScore, countryCode);
    }

    public static IntelResult failed() {
        return new IntelResult(false, false, false, false, false, false, 0, null);
    }

    public boolean isSuccess() {
        return success;
    }

    public boolean shouldBlock(IntelSettings config) {
        if (!success) {
            return false;
        }
        if (!config.getAllowCountryCodes().isEmpty()) {
            if (countryCode == null || !config.getAllowCountryCodes().contains(countryCode)) {
                return true;
            }
        }
        if (countryCode != null && config.getBlockCountryCodes().contains(countryCode)) {
            return true;
        }
        if (config.isBlockResidentialProxy() && residentialProxy) {
            return true;
        }
        if (config.isBlockProxy() && proxy) {
            return true;
        }
        if (config.isBlockVpn() && vpn) {
            return true;
        }
        if (config.isBlockTor() && tor) {
            return true;
        }
        if (config.isBlockHosting() && hosting) {
            return true;
        }
        int minFraud = config.getMinFraudScore();
        if (minFraud > 0 && fraudScore >= minFraud) {
            return true;
        }
        return false;
    }
}
