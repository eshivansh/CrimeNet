package com.crimenet.security.mfa;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * RFC 6238 TOTP implementation compatible with Google Authenticator,
 * Microsoft Authenticator, Authy, and hardware tokens: HMAC-SHA1, 30-second step, 6 digits.
 *
 * Free, open-source, and dependency-free (pure standard library crypto).
 */
@Service
public class TotpService {

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final int SECRET_BYTES = 20;      // 160-bit secret
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final int[] DIGITS_POWER = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000};

    private final SecureRandom secureRandom = new SecureRandom();

    /** Generates a fresh random secret, Base32-encoded for QR/manual entry. */
    public String generateSecret() {
        byte[] raw = new byte[SECRET_BYTES];
        secureRandom.nextBytes(raw);
        return Base32Util.encode(raw);
    }

    /**
     * Builds the otpauth:// provisioning URI for standard authenticator apps.
     */
    public String buildProvisioningUri(String base32Secret, String issuer, String accountLabel) {
        String encodedIssuer = urlEncode(issuer);
        String encodedLabel = urlEncode(issuer + ":" + accountLabel);
        return "otpauth://totp/" + encodedLabel
                + "?secret=" + base32Secret
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1"
                + "&digits=" + CODE_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    /** Current RFC 6238 time-step counter. */
    public long currentTimeStep() {
        return Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
    }

    /**
     * Verifies a submitted code against the given secret, tolerating clock drift of +/- 1 step.
     *
     * @return the matched time-step counter if valid, or -1 if invalid.
     */
    public long verify(String base32Secret, String submittedCode) {
        if (submittedCode == null || !submittedCode.matches("\\d{" + CODE_DIGITS + "}")) {
            return -1;
        }
        long step = currentTimeStep();
        for (long candidate = step - 1; candidate <= step + 1; candidate++) {
            String expected = generateCode(base32Secret, candidate);
            if (constantTimeEquals(expected, submittedCode)) {
                return candidate;
            }
        }
        return -1;
    }

    /** Generates the 6-digit code for a specific time step. */
    public String generateCode(String base32Secret, long timeStepCounter) {
        try {
            byte[] key = Base32Util.decode(base32Secret);
            byte[] msg = new byte[8];
            long value = timeStepCounter;
            for (int i = 7; i >= 0; i--) {
                msg[i] = (byte) (value & 0xFF);
                value >>= 8;
            }

            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(msg);

            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % DIGITS_POWER[CODE_DIGITS];
            return String.format("%0" + CODE_DIGITS + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
