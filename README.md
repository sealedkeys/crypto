# SealedKeys — Encryption Layer

This repository contains the client-side encryption code that powers [SealedKeys](https://sealedkeys.com) — a zero-knowledge password and secrets manager for technical teams.

The rest of the application (server, API, UI) is closed-source. This module is published so that anyone can audit the code that handles your secrets — without trusting our word for it.

---

## What's in here

| File | Purpose |
|------|---------|
| `crypto.ts` | Key derivation, encryption, decryption, password generation |
| `offline-viewer.html` | Self-contained vault viewer — works with no internet connection |

---

## How it works

### 1. Key derivation (client-only)

Your master password never leaves your browser in usable form. A 256-bit AES-GCM vault key is derived locally using PBKDF2:

```
salt      = UTF8(lowercase(email) + "sealedkeys_v1")
vault_key = PBKDF2(password, salt, iterations=600_000, hash=SHA-256, keylen=256)
```

The email is included in the salt so that the same password on two different accounts produces different vault keys. The `sealedkeys_v1` suffix domain-separates keys from any other PBKDF2 usage.

The vault key is marked `extractable: false` via the Web Crypto API — the raw key bytes never exist in the JavaScript heap.

### 2. Encryption (client-only)

Each secret's sensitive fields are serialised as JSON and encrypted before being sent to the server:

```
iv             = random 12 bytes (from crypto.getRandomValues)
ciphertext     = AES-256-GCM(vault_key, JSON(secret_fields), aad=item_id)
wire_format    = "!" + base64url(iv || ciphertext)
```

The item's database ID is included as AES-GCM additional authenticated data (AAD), cryptographically binding each ciphertext to its row. A ciphertext cannot be moved to a different item without decryption failing.

### 3. What the server receives

```
{ name, url, tags, encryptedData }
```

The server stores only the encrypted blob plus non-sensitive metadata. It has no access to the vault key and cannot decrypt items. A full database breach exposes no plaintext secrets.

### 4. Decryption (client-only)

When you open your vault, encrypted blobs are fetched from the server and decrypted in the browser:

```
(iv, ciphertext) = base64url_decode(wire_format[1:])
secret_fields    = JSON.parse(AES-256-GCM-decrypt(vault_key, ciphertext, aad=item_id))
```

### Wire format versions

| Prefix | Format | AAD |
|--------|--------|-----|
| none | `base64url(iv[12] \|\| ciphertext)` | none (legacy v1) |
| `!` | `"!" + base64url(iv[12] \|\| ciphertext)` | item ID (current v2) |

`!` is not a valid base64url character, making version detection unambiguous.

---

## Offline viewer

`offline-viewer.html` is a self-contained HTML file with zero external dependencies. It implements the same KDF and decryption scheme as the main application and works without an internet connection or a SealedKeys account.

To use it:

1. Export your vault from SealedKeys (Settings → Export → Encrypted backup)
2. Open `offline-viewer.html` in any modern browser
3. Paste the exported JSON and enter your master password
4. Your vault is decrypted locally — nothing leaves the browser

Press `Escape` at any time to wipe all data from memory.

This file is the foundation of our [data portability commitment](https://sealedkeys.com/security): if SealedKeys shuts down, your data remains decryptable using open-source tools.

---

## Implementation notes

**No third-party cryptography.** This module uses only `window.crypto.subtle` — the browser's built-in Web Crypto API. There are no npm dependencies for the cryptographic operations.

**Rejection sampling.** Password generation uses rejection sampling to eliminate modulo bias when selecting characters from the pool.

**Known limitations (documented honestly)**

- The master password is transmitted over HTTPS for bcrypt authentication server-side. A future release will replace this with SRP (Secure Remote Password) so the server never receives the raw password.
- The KDF is PBKDF2-SHA256. Argon2id provides stronger resistance against GPU-based attacks and is on the roadmap.
- Item names and URLs are stored unencrypted on the server (used for search). If this is a concern, use generic names.

These limitations are also documented on the [security page](https://sealedkeys.com/security).

---

## Verifying the live application

The encryption module is loaded as part of the Next.js application bundle. To verify that the live site runs this code:

1. Open https://sealedkeys.com in a browser
2. Open DevTools → Sources → search for `sealedkeys_v1`, `PBKDF2`, or `AES-GCM`
   - Function names are minified in the production bundle, but string literals survive intact
   - You should find `sealedkeys_v1` in the login, register, and vault page chunks
3. The surrounding code should show PBKDF2 key derivation feeding into AES-GCM encrypt/decrypt operations, matching the implementation here

Network inspection will confirm that only `encryptedData` (ciphertext) is sent to the API — never plaintext secret values.

---

## Cryptographic parameters

| Parameter | Value |
|-----------|-------|
| KDF | PBKDF2 |
| KDF hash | SHA-256 |
| KDF iterations | 600,000 |
| KDF salt | `lowercase(email) + "sealedkeys_v1"` |
| Cipher | AES-256-GCM |
| IV size | 12 bytes (96 bits) |
| IV generation | `crypto.getRandomValues` |
| AAD | Item database ID (v2 format) |
| Key extractable | `false` |
| Wire encoding | base64url |

---

## Audit

An independent OWASP web-application security assessment was completed in May 2026 covering authentication, session security, IDOR, broken access control, input validation, injection and transport security. The full report is available at [sealedkeys.com/security](https://sealedkeys.com/security).

---

## Licence

MIT — see [LICENSE](LICENSE).

The remainder of the SealedKeys application is proprietary. This repository contains only the client-side encryption layer.

---

## Contact

Security issues: hello@sealedkeys.com  
Everything else: [sealedkeys.com](https://sealedkeys.com)
