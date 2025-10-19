import java.util.*;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

/**
 * Secure AuthSystem implementation for CA1.
 * - PBKDF2WithHmacSHA256 for password hashing with per-user salt
 * - Constant-time comparisons
 * - User enumeration mitigation (always perform hashing)
 * - Account lockout after configurable failed attempts
 * - Cryptographically secure session tokens
 */
public class AuthSystem {
    private final Map<String, User> users = new HashMap<>();
    private final Map<String, Session> sessions = new HashMap<>();

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String HASH_ALGO = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int ITERATIONS = 100_000; // reasonable work factor
    private static final int KEY_LENGTH = 256; // bits

    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_MS = 5 * 60 * 1000L; // 5 minutes
    private static final long SESSION_TTL_MS = 30 * 60 * 1000L; // 30 minutes

    // Used to consume time in mismatched-length comparisons to avoid timing leaks and analyzer warnings
    private static final java.util.concurrent.atomic.AtomicInteger timingPad = new java.util.concurrent.atomic.AtomicInteger(0);

    private static class User {
        final String passwordHash; // base64
        final String salt; // base64
        int failedAttempts = 0;
        long lockoutUntil = 0;

        User(String passwordHash, String salt) {
            this.passwordHash = passwordHash;
            this.salt = salt;
        }
    }

    private static class Session {
        final String username;
        final long createdAt;

        Session(String username, long createdAt) {
            this.username = username;
            this.createdAt = createdAt;
        }
    }

    /**
     * Register a new user. Returns false if username already exists.
     */
    public synchronized boolean register(String username, char[] password) {
        if (users.containsKey(username)) return false;
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        String saltB64 = Base64.getEncoder().encodeToString(salt);
        String hash = hashPassword(password, salt);
        // zero password char array
        Arrays.fill(password, '\0');
        users.put(username, new User(hash, saltB64));
        return true;
    }

    /**
     * Attempt login. Returns session token on success, null otherwise.
     * This method resists user enumeration and timing attacks.
     */
    public synchronized String login(String username, char[] password) {
        User user = users.get(username);
        boolean userExists = (user != null);

        // Prepare salt and expected hash. If user doesn't exist, use a random salt and a dummy hash
        byte[] saltBytes;
        String expectedHash;
        if (userExists) {
            saltBytes = Base64.getDecoder().decode(user.salt);
            expectedHash = user.passwordHash;
        } else {
            saltBytes = new byte[SALT_BYTES];
            secureRandom.nextBytes(saltBytes);
            expectedHash = hashPassword("dummy".toCharArray(), saltBytes);
        }

        // If account is locked, perform dummy work and return null
        if (userExists && user.lockoutUntil > System.currentTimeMillis()) {
            // perform hashing to keep timing similar
            hashPassword(password, saltBytes);
            Arrays.fill(password, '\0');
            return null;
        }

        String providedHash = hashPassword(password, saltBytes);
        // zero password input
        Arrays.fill(password, '\0');

        boolean passwordMatches = constantTimeEquals(expectedHash, providedHash);

        // If user exists and password matches, create session
        if (userExists && passwordMatches) {
            user.failedAttempts = 0;
            user.lockoutUntil = 0;
            String token = generateSessionToken();
            sessions.put(token, new Session(username, System.currentTimeMillis()));
            return token;
        }

        // If user exists and password failed, increment counter and possibly lock
        if (userExists) {
            user.failedAttempts++;
            if (user.failedAttempts >= MAX_ATTEMPTS) {
                user.lockoutUntil = System.currentTimeMillis() + LOCKOUT_MS;
                user.failedAttempts = 0; // reset after lock
            }
        }

        return null;
    }

    /**
     * Validate session token. Uses constant-time compare and enforces TTL.
     */
    public synchronized boolean isSessionValid(String token) {
        if (token == null) return false;
        Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Session> e = it.next();
            String storedToken = e.getKey();
            Session s = e.getValue();

            if (System.currentTimeMillis() - s.createdAt > SESSION_TTL_MS) {
                it.remove();
                continue;
            }
            if (constantTimeEquals(storedToken, token)) return true;
        }
        return false;
    }

    // ---- Helpers ----
    private static String hashPassword(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGO);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException("Hashing failed", ex);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (aBytes.length != bBytes.length) {
            // Run through the loop anyway to keep timing consistent and update TIMING_PAD
            int max = Math.max(aBytes.length, bBytes.length);
            int acc = 0;
            for (int i = 0; i < max; i++) {
                byte x = i < aBytes.length ? aBytes[i] : 0;
                byte y = i < bBytes.length ? bBytes[i] : 0;
                acc |= x ^ y;
            }
            timingPad.getAndAdd(acc);
            return false;
        }
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }

    private static String generateSessionToken() {
        byte[] token = new byte[32];
        secureRandom.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
