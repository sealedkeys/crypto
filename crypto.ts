/**
 * SealedKeys – Client-Side Encryption Module
 *
 * SECURITY MODEL (Zero-Knowledge Architecture):
 * ─────────────────────────────────────────────
 * 1. The user's master password never leaves the browser in any usable form.
 * 2. A vault key is derived client-side using PBKDF2 (600,000 iterations, SHA-256).
 * 3. Every secret value is encrypted with AES-256-GCM before being sent to the server.
 * 4. The server stores only ciphertext + IV. It cannot decrypt vault items.
 * 5. A breach of the server's database exposes zero plaintext secrets.
 *
 * ENCRYPTION WIRE FORMAT:
 * ─────────────────────────────────────────────
 * encryptedData = base64url( iv[12 bytes] + ciphertext )
 * where ciphertext = AES-256-GCM(vaultKey, JSON.stringify(plaintext))
 *
 * KNOWN MVP LIMITATIONS (see ROADMAP.md):
 * ─────────────────────────────────────────────
 * - TODO: The master password is sent to the server for bcrypt auth. A production
 *   implementation should use SRP (Secure Remote Password) so the server never
 *   receives the raw password even over HTTPS.
 * - TODO: Vault key is held in Zustand memory. Add session lock on idle timeout.
 * - TODO: Upgrade PBKDF2 to Argon2id (via WASM) for stronger KDF against GPU attacks.
 * - TODO: Implement key versioning so individual items can be re-encrypted after
 *   a password change without decrypting the entire vault.
 *
 * This module uses the browser's native Web Crypto API (no external dependencies).
 * All functions are async and will throw on decryption failure (e.g. tampered data).
 */

const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_HASH = "SHA-256";
const KDF_SALT_SUFFIX = "sealedkeys_v1"; // append to email for KDF salt

// Wire format versioning
// v1 (legacy): base64url(iv[12] + ciphertext)         — no AAD
// v2 (current): "!" + base64url(iv[12] + ciphertext)  — AAD = itemId
// "!" is not a valid base64url character, so it is unambiguous as a version marker.
const V2_PREFIX = "!";

/** Import raw bytes as a CryptoKey for use with PBKDF2 */
async function importPasswordKey(password: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, [
    "deriveKey",
  ]);
}

/**
 * Derive a 256-bit AES-GCM vault key from the master password + email.
 *
 * The email is used as part of the salt to ensure that the same password
 * on two different accounts produces different vault keys.
 *
 * @param masterPassword – the user's master password (never stored)
 * @param email – the user's email address (used as KDF salt input)
 */
export async function deriveVaultKey(
  masterPassword: string,
  email: string
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const salt = enc.encode(email.toLowerCase() + KDF_SALT_SUFFIX);
  const passwordKey = await importPasswordKey(masterPassword);

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false, // not extractable – key cannot leave memory
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt a vault item's sensitive fields.
 *
 * When itemId is supplied the output is v2 format ("!" prefix + AAD = itemId),
 * which cryptographically binds the ciphertext to the item's database row.
 * Without itemId the legacy v1 format is produced (no prefix, no AAD).
 *
 * @param vaultKey – derived by deriveVaultKey()
 * @param plaintext – any JSON-serialisable object with the secret fields
 * @param itemId – the vault item's database id (binds ciphertext to row via AAD)
 * @returns wire-format string (see top of file)
 */
export async function encryptVaultItem(
  vaultKey: CryptoKey,
  plaintext: Record<string, unknown>,
  itemId?: string
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(plaintext));

  const params: AesGcmParams = itemId
    ? { name: "AES-GCM", iv, additionalData: enc.encode(itemId) }
    : { name: "AES-GCM", iv };

  const ciphertext = await crypto.subtle.encrypt(params, vaultKey, data);

  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);

  const encoded = bufferToBase64url(combined);
  return itemId ? V2_PREFIX + encoded : encoded;
}

/**
 * Decrypt a vault item's sensitive fields.
 *
 * Auto-detects wire format version. For v2 data (starts with "!") the itemId
 * must be supplied and must match the one used during encryption, or decryption
 * will fail with a DOMException (authentication tag mismatch).
 *
 * @param vaultKey – must be the same key used to encrypt
 * @param encryptedData – wire-format string produced by encryptVaultItem()
 * @param itemId – required for v2 data; ignored for legacy v1 data
 * @returns the original plaintext object
 */
export async function decryptVaultItem<T = Record<string, unknown>>(
  vaultKey: CryptoKey,
  encryptedData: string,
  itemId?: string
): Promise<T> {
  const isV2 = encryptedData.startsWith(V2_PREFIX);
  const raw = isV2 ? encryptedData.slice(1) : encryptedData;

  const combined = base64urlToBuffer(raw);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const enc = new TextEncoder();
  const params: AesGcmParams =
    isV2 && itemId
      ? { name: "AES-GCM", iv, additionalData: enc.encode(itemId) }
      : { name: "AES-GCM", iv };

  const plaintext = await crypto.subtle.decrypt(params, vaultKey, ciphertext);

  const dec = new TextDecoder();
  return JSON.parse(dec.decode(plaintext)) as T;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function bufferToBase64url(buffer: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buffer.byteLength; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlToBuffer(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer;
}

// ─── Password Generator ───────────────────────────────────────────────────────

const CHARSET = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
};

export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

/**
 * Generate a cryptographically secure random password using Web Crypto.
 * Uses rejection sampling to avoid modulo bias.
 */
export function generatePassword(opts: PasswordOptions): string {
  let pool = CHARSET.lowercase;
  if (opts.uppercase) pool += CHARSET.uppercase;
  if (opts.digits) pool += CHARSET.digits;
  if (opts.symbols) pool += CHARSET.symbols;

  const poolLen = pool.length;
  let result = "";

  // Ensure at least one character from each enabled set
  const required: string[] = [
    CHARSET.lowercase[randomIndex(CHARSET.lowercase.length)],
  ];
  if (opts.uppercase) required.push(CHARSET.uppercase[randomIndex(CHARSET.uppercase.length)]);
  if (opts.digits) required.push(CHARSET.digits[randomIndex(CHARSET.digits.length)]);
  if (opts.symbols) required.push(CHARSET.symbols[randomIndex(CHARSET.symbols.length)]);

  for (let i = required.length; i < opts.length; i++) {
    required.push(pool[randomIndex(poolLen)]);
  }

  // Shuffle with Fisher-Yates
  for (let i = required.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [required[i], required[j]] = [required[j], required[i]];
  }

  result = required.join("");
  return result;
}

function randomIndex(max: number): number {
  // Rejection sampling to eliminate modulo bias
  const randomBytes = new Uint32Array(1);
  const limit = 0x100000000 - (0x100000000 % max);
  let value: number;
  do {
    crypto.getRandomValues(randomBytes);
    value = randomBytes[0];
  } while (value >= limit);
  return value % max;
}

// ─── Password Strength ────────────────────────────────────────────────────────

export interface PasswordStrength {
  score: 0 | 1 | 2 | 3 | 4; // 0=terrible 4=strong
  label: string;
  color: string;
}

export function assessPasswordStrength(password: string): PasswordStrength {
  if (!password) return { score: 0, label: "Empty", color: "text-red-500" };

  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  // Clamp to 0-4
  const clamped = Math.min(4, score) as 0 | 1 | 2 | 3 | 4;

  const labels: Record<0 | 1 | 2 | 3 | 4, string> = {
    0: "Very weak",
    1: "Weak",
    2: "Fair",
    3: "Good",
    4: "Strong",
  };
  const colors: Record<0 | 1 | 2 | 3 | 4, string> = {
    0: "text-red-500",
    1: "text-orange-500",
    2: "text-yellow-500",
    3: "text-blue-400",
    4: "text-emerald-400",
  };

  return { score: clamped, label: labels[clamped], color: colors[clamped] };
}
