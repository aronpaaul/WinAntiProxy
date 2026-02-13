package im.aronpaul.winantiproxy.detect;

import java.net.InetAddress;

public final class CidrMatcher {

    private final byte[] network;
    private final int prefixLength;

    public CidrMatcher(byte[] network, int prefixLength) {
        this.network = network;
        this.prefixLength = prefixLength;
    }

    public boolean matches(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length != network.length) {
            return false;
        }
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (addr[i] != network[i]) {
                return false;
            }
        }
        if (remainingBits > 0) {
            int mask = 0xFF << (8 - remainingBits);
            int a = addr[fullBytes] & 0xFF;
            int n = network[fullBytes] & 0xFF;
            return (a & mask) == (n & mask);
        }
        return true;
    }

    public static CidrMatcher from(InetAddress address, int prefixLength) {
        return new CidrMatcher(address.getAddress(), prefixLength);
    }
}
