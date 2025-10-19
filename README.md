Secure Application Programming CA1

How to build and run (PowerShell):

Build with Maven:

```powershell
mvn -f .\pom.xml clean package
```

Run the demo Main class (prints registration/login/lockout flows):

```powershell
java -jar .\target\Secure-Application-Programming-CA1-1.0.0.jar
```

Run unit tests:

```powershell
mvn -f .\pom.xml test
```

Grading checklist (quick):
- Password hashing: PBKDF2WithHmacSHA256 with per-user salt (see `AuthSystem.hashPassword`).
- No plaintext passwords: method takes `char[]` and zeroes input after hashing.
- User enumeration: `login` computes a dummy hash for non-existent users to keep timing similar.
- Brute-force defence: `MAX_ATTEMPTS` and `LOCKOUT_MS` with per-user failedAttempts and lockoutUntil.
- Session tokens: cryptographically-random 32-byte tokens encoded as URL-safe Base64 (see `generateSessionToken`).
- Constant-time comparisons: `constantTimeEquals` used for password and token comparisons.

Files to grade:
- `src/main/java/com/eoin/auth/AuthSystem.java` (primary file)
- `src/main/java/com/eoin/auth/Main.java` (demo runner)
- `src/test/java/com/eoin/auth/AuthSystemTest.java` (unit tests)
- `Report.md` (draft of the 2-page report)

Notes:
- The code is intentionally in a named package `com.eoin.auth` to follow Java conventions.
- For a more modern KDF (Argon2) I can add a dependency and refactor on request.
