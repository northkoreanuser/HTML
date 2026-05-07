// ────────────────────────────────────────────────
//  pbkdf2.js — PBKDF2-SHA256 키 파생
//  deriveKey(password, salt) → CryptoKey
// ────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 600_000;
const _enc_pbkdf2 = new TextEncoder();

async function deriveKey_pbkdf2(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw', _enc_pbkdf2.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}
