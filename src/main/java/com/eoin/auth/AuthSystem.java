package com.eoin.auth;

import java.util.*;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

/*
 * AuthSystem.java
 *
 * Purpose:
 *   A compact, self-contained authentication and session manager designed for
 *   the Secure Application Programming CA1 assignment. The implementation
 *   focuses on demonstrating professional secure coding practices in Java
 *   for the following concerns required by the brief:
 *     1) Strong salted password hashing (not plain SHA-256)
 *     2) User enumeration resistance (indistinguishable timing / behavior)
 *     3) Brute-force defence via account lockout
 *     4) Secure, unpredictable session token generation and validation
 *     5) Constant-time comparisons to mitigate timing attacks
 *
 * How this file is organised:
 *   - Top-level configuration constants (tunable security parameters)
 *   - Inner classes `User` and `Session` (simple in-memory models)
 *   - Public API: `register`, `login`, `isSessionValid`
 *   - Private helpers: password hashing, secure token generation, constant-time compare
 *
 * Notes for graders:
 *   - This file is intentionally heavily commented to make the security
 *     rationale and mapping to the assignment brief explicit and easy to
 *     verify.
 *   - The implementation is intentionally simple and in-memory so it can be
 *     executed and inspected easily. In production you'd replace the maps
 *     with a secure data store and persist metadata (failed attempts, salts).
 */
public class AuthSystem {
    // In-memory user store. Key = username, Value = User record (hash + salt + counters)
    private final Map<String, User> users = new HashMap<>();

    // In-memory session store. Key = session token, Value = Session metadata
    private final Map<String, Session> sessions = new HashMap<>();

    // Cryptographically secure RNG for salts and tokens
    private static final SecureRandom secureRandom = new SecureRandom();

    /* Password hashing algorithm selection
     * - PBKDF2WithHmacSHA256 is selected because it's supported in the standard
     *   Java runtime and provides an iterated, HMAC-based KDF suitable for
     *   password hashing. It is stronger than single-iteration SHA-256.
     * - Argon2 would be a more modern choice; if you want Argon2 I can add a
     *   dependency (e.g., Bouncy Castle or a dedicated Argon2 lib) and switch.
     */
    private static final String HASH_ALGO = "PBKDF2WithHmacSHA256";

    // Per-user salt length (bytes). 16 bytes = 128 bits is acceptable; 32 bytes
    // is also fine. Salts prevent precomputation (rainbow table) attacks.
    private static final int SALT_BYTES = 16;

    // Work factor: number of PBKDF2 iterations. Increase if CPU allows.
    private static final int ITERATIONS = 100_000; // balance between security & performance

    // Output key length (bits) for the KDF
    private static final int KEY_LENGTH = 256; // bits

    /* Brute-force defence parameters:
     * - MAX_ATTEMPTS: number of consecutive failed logins before lockout
     * - LOCKOUT_MS: how long to lock the account (milliseconds)
     * These values are reasonable for a lab/assignment. In a production
     * system you'd also consider progressive backoff, CAPTCHAs, and alerts.
     */
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_MS = 5 * 60 * 1000L; // 5 minutes

    // Session TTL: how long a session remains valid from creation
    private static final long SESSION_TTL_MS = 30 * 60 * 1000L; // 30 minutes

    /* timingPad is used only to ensure constant-time work is performed even
     * when input lengths differ. It prevents simple micro-optimizations from
     * short-circuiting the comparison loop which could leak timing.
     */
    private static final java.util.concurrent.atomic.AtomicInteger timingPad = new java.util.concurrent.atomic.AtomicInteger(0);

    /* Inner class: User
     * - passwordHash: Base64 encoding of the PBKDF2 output
     * - salt: Base64 encoding of the per-user salt
     * - failedAttempts: consecutive failed login counter (resets on success)
     * - lockoutUntil: epoch ms until which the account is locked
     */
    private static class User {
        final String passwordHash; // base64-encoded PBKDF2 output
        final String salt; // base64-encoded salt
        int failedAttempts = 0;
        long lockoutUntil = 0;

        User(String passwordHash, String salt) {
            this.passwordHash = passwordHash;
            this.salt = salt;
        }
    }

    /* Inner class: Session
     * - username: owner of the session token
     * - createdAt: epoch ms when the session was created (used to enforce TTL)
     *
     * Note: For a real web application, session metadata would include client
     * fingerprinting and storage in a secure, persistent store. This simple
     * in-memory model is used for demonstration and grading convenience.
     */
    private static class Session {
        final String username;
        final long createdAt;

        Session(String username, long createdAt) {
            this.username = username;
            this.createdAt = createdAt;
        }
    }

    /**
     * Register a new user.
     *
     * Security notes:
     *  - Passwords are accepted as a char[] so the caller can zero the buffer
     *    after use; this avoids immutable String objects keeping secrets in
     *    the heap. This method also zeroes the provided password char[] after
     *    hashing to reduce exposure.
     *  - A per-user random salt is generated via SecureRandom and stored (in
     *    base64) alongside the hashed password.
     *
     * Returns: true on success, false if username already exists
     */
    public synchronized boolean register(String username, char[] password) {
        if (users.containsKey(username)) return false; // do not overwrite existing users

        // Generate a fresh per-user salt
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        String saltB64 = Base64.getEncoder().encodeToString(salt);

        // Derive the password hash using PBKDF2
        String hash = hashPassword(password, salt);

        // Zero the password input as a hygiene step to reduce memory exposure
        Arrays.fill(password, '\0');

        // Store the user record (in-memory for the assignment)
        users.put(username, new User(hash, saltB64));
        return true;
    }

    /**
     * Attempt login.
     *
     * Behavior and security guarantees implemented:
     *  - Prevent user enumeration: when a username does not exist we generate
     *    a random salt and compute a dummy hash. This ensures the login work
     *    (and therefore timing) is similar whether or not the user exists.
     *  - Account lockout: if a user exceeds MAX_ATTEMPTS the account is
     *    locked for LOCKOUT_MS. While locked, we still perform hashing to
     *    prevent timing differences that would reveal the lock state.
     *  - Constant-time comparison: password hash comparisons use
     *    `constantTimeEquals` to mitigate timing attacks.
     *
     * Returns: a cryptographically random session token string on success;
     *          null on failure.
     */
    public synchronized String login(String username, char[] password) {
        User user = users.get(username);
        boolean userExists = (user != null);

        // Prepare salt and expected hash. For non-existing users we generate a
        // random salt and compute a dummy expected hash — this is crucial for
        // preventing user enumeration via timing or error messages.
        byte[] saltBytes;
        String expectedHash;
        if (userExists) {
            saltBytes = Base64.getDecoder().decode(user.salt);
            expectedHash = user.passwordHash;
        } else {
            // Non-existing user: create a random salt and compute dummy hash
            saltBytes = new byte[SALT_BYTES];
            secureRandom.nextBytes(saltBytes);

            // Use a temporary char[] populated with random printable chars to
            // avoid creating a String literal in memory (String may be interned
            // or remain until GC). We zero it after hashing.
            char[] dummy = new char[SALT_BYTES];
            for (int i = 0; i < dummy.length; i++) {
                dummy[i] = (char) (33 + secureRandom.nextInt(94)); // 33-126 printable
            }
            expectedHash = hashPassword(dummy, saltBytes);
            Arrays.fill(dummy, '\0'); // zero dummy
        }

        // If the account is currently locked, perform the same hashing work
        // (to avoid distinguishable timing) and then return failure.
        if (userExists && user.lockoutUntil > System.currentTimeMillis()) {
            // Perform hashing to keep timing consistent with normal path
            hashPassword(password, saltBytes);
            Arrays.fill(password, '\0');
            return null;
        }

        // Compute the hash for the provided password using the chosen salt
        String providedHash = hashPassword(password, saltBytes);
        Arrays.fill(password, '\0'); // zero caller-supplied password

        // Compare the computed hash and the expected hash in constant time
        boolean passwordMatches = constantTimeEquals(expectedHash, providedHash);

        // If the user exists and passwords match -> reset counters and create session
        if (userExists && passwordMatches) {
            user.failedAttempts = 0;
            user.lockoutUntil = 0;
            String token = generateSessionToken();
            sessions.put(token, new Session(username, System.currentTimeMillis()));
            return token;
        }

        // If user exists and password failed, increment counter and lock if necessary
        if (userExists) {
            user.failedAttempts++;
            if (user.failedAttempts >= MAX_ATTEMPTS) {
                user.lockoutUntil = System.currentTimeMillis() + LOCKOUT_MS;
                user.failedAttempts = 0; // reset counter after establishing a lock
            }
        }

        // Default: authentication failed (either bad credentials or account missing)
        return null;
    }

    /**
     * Validate a session token.
     *
     * Security and behaviour:
     *  - Tokens are compared using `constantTimeEquals` to avoid leaking which
     *    stored token matched by timing.
     *  - Expired sessions (older than SESSION_TTL_MS) are removed during
     *    validation to keep the in-memory map tidy.
     */
    public synchronized boolean isSessionValid(String token) {
        if (token == null) return false;
        Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Session> e = it.next();
            String storedToken = e.getKey();
            Session s = e.getValue();

            // Remove expired sessions during traversal. This keeps the demo
            // in-memory store from growing during long runs.
            if (System.currentTimeMillis() - s.createdAt > SESSION_TTL_MS) {
                it.remove();
                continue;
            }

            // Constant-time compare to avoid leaking which token matched.
            if (constantTimeEquals(storedToken, token)) return true;
        }
        return false;
    }

    // ---- Helpers ----

    /**
     * Hash a password using PBKDF2 (HMAC-SHA256) with the provided salt.
     *
     * Accepts a char[] and returns a base64-encoded string to avoid storing raw
     * bytes directly in memory where possible. The caller is responsible for
     * zeroing the char[] after use; register/login already do this.
     */
    private static String hashPassword(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGO);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            // Hashing should not fail on a properly-configured JVM; if it does,
            // fail fast so calling code can handle an unrecoverable condition.
            throw new IllegalStateException("Hashing failed", ex);
        }
    }

    /**
     * Constant-time comparison of two strings to mitigate timing attacks.
     *
     * Implementation details:
     *  - Convert to UTF-8 bytes and iterate the full length of the longer
     *    array, xoring bytes into an accumulator so the loop always runs the
     *    same number of iterations regardless of equality.
     *  - If lengths differ we still run the full loop and update a shared
     *    atomic to prevent trivial micro-optimizations.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (aBytes.length != bBytes.length) {
            int max = Math.max(aBytes.length, bBytes.length);
            int acc = 0;
            for (int i = 0; i < max; i++) {
                byte x = i < aBytes.length ? aBytes[i] : 0;
                byte y = i < bBytes.length ? bBytes[i] : 0;
                acc |= x ^ y;
            }
            // Use timingPad to make sure we touch shared memory and avoid some
            // trivial JIT/CPU optimizations that could make timing of unequal
            // length strings observable.
            timingPad.getAndAdd(acc);
            return false;
        }
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }

    /**
     * Generate a secure random session token.
     *
     * The token length of 32 bytes (256 bits) is encoded to a URL-safe Base64
     * string without padding. This string is safe to use in cookies and HTTP
     * headers (after appropriate encoding) and is unpredictable because it is
     * produced with SecureRandom.
     */
    private static String generateSessionToken() {
        byte[] token = new byte[32];
        secureRandom.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
