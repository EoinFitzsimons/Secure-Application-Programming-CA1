Security Audit & Remediation Report

Vulnerability Analysis

1. Plain-text password storage (Confidentiality)
   - Original code stored passwords directly in memory as Strings. This exposes credentials to memory disclosure and persistent logs. 

2. Predictable/weak session tokens (Confidentiality, Integrity)
   - Original session tokens were constructed from username and timestamp (predictable).

3. User enumeration via early returns (Confidentiality / Defence in Depth)
   - The login method returned early if a username did not exist, allowing attackers to probe valid usernames.

4. Timing attack on string equality (Confidentiality)
   - Using String.equals to compare passwords leaks timing differences that can reveal partial matches.

5. No brute-force mitigations (Availability / Defence in Depth)
   - No account lockout or throttling, making brute-force attacks feasible.

Remediation Summary

1. Strong password hashing
   - Implemented PBKDF2WithHmacSHA256 with per-user 16-byte salts and 100,000 iterations, producing a 256-bit derived key. PBKDF2 is widely supported and resistant to GPU/ASIC brute-force when iteration counts are reasonable. Iteration count chosen for reasonable CPU cost on modern hardware; this is configurable.

2. Prevent user enumeration and timing leaks
   - Login always performs hashing and a constant-time comparison, even for non-existent users. A random salt and dummy hash are used for non-existent accounts so timing is similar.

3. Constant-time comparisons
   - Implemented a constant-time byte-wise comparison that runs over the full length and does not short-circuit. When lengths differ we still iterate over the maximum length and update a timing pad to avoid early exits.

4. Brute-force defence
   - Track failed attempts per user and lock the account for 5 minutes after 5 consecutive failed attempts. This provides a balance between security and usability.

5. Secure session tokens
   - Generate 32-byte random tokens using SecureRandom and URL-safe Base64 encoding. Session tokens have a TTL (30 minutes) and are validated using constant-time comparison.

Trade-offs

- Account lockout vs usability: Locking accounts after repeated failures reduces risk from brute-force attacks but may allow denial-of-service against legitimate users if an attacker triggers lockouts. To balance this, the lockout window was set to 5 minutes and failed attempt counters reset on successful login; in production, consider progressive delays, CAPTCHA, or notifying users instead of hard lockouts.

- PBKDF2 iterations vs performance: Higher iterations increase attack cost but also raise server CPU usage. The chosen 100,000 iterations provide reasonable defense on modern hardware but should be tuned per deployment and reviewed periodically.

Notes & How to Run

Files added:
- `AuthSystem.java` — secure authentication implementation using PBKDF2, constant-time checks, lockout and session management.
- `Main.java` — small test harness demonstrating registration, login, lockout and session validation.

To compile and run (from CA1 folder):

javac AuthSystem.java Main.java
java Main

Conclusion

The provided vulnerabilities were addressed with industry-standard mitigations. Further improvements for production include: persisting users in a secure database, using a dedicated key derivation library (e.g., Argon2 via libs), adding logging/monitoring of suspicious activity, multi-factor authentication, and stronger session handling with secure cookies and TLS enforcement.
