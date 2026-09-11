package com.crimenet.security.mfa;

import java.util.Arrays;

/**
 * Minimal RFC 4648 Base32 codec (no padding on encode, tolerant on decode).
 *
 * Dependency-free and self-contained: Base32 is the wire format every
 * TOTP authenticator app (Google Authenticator, Authy, 1Password, etc.)
 * expects for the shared secret.
 */
public final class Base32Util {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] LOOKUP = new int[128];

    static {
        Arrays.fill(LOOKUP, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            LOOKUP[ALPHABET[i]] = i;
        }
    }

    private Base32Util() {
    }

    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                sb.append(ALPHABET[index]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.append(ALPHABET[index]);
        }
        return sb.toString();
    }

    public static byte[] decode(String base32) {
        String cleaned = base32.trim().toUpperCase().replace("=", "");
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : cleaned.toCharArray()) {
            if (c >= LOOKUP.length || LOOKUP[c] == -1) {
                continue; // skip formatting chars (spaces/dashes)
            }
            buffer = (buffer << 5) | LOOKUP[c];
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }
}
