// ────────────────────────────────────────────────
//  aes.js — AES-256-GCM 암호화 / 복호화
//  의존: argon2.js · pbkdf2.js · bcrypt.js · xor.js
// ────────────────────────────────────────────────

const SALT_LEN = 16;
const IV_LEN   = 12;
const _enc_aes = new TextEncoder();
const _dec_aes = new TextDecoder();

// 알고리즘 → deriveKey 함수 라우팅
async function deriveKey(password, salt, algorithm = 'argon2id') {
    switch (algorithm) {
        case 'pbkdf2':   return deriveKey_pbkdf2(password, salt);
        case 'bcrypt':   return deriveKey_bcrypt(password, salt);
        case 'argon2id':
        default:         return deriveKey_argon2id(password, salt);
    }
}

// ── 암호화 ─────────────────────────────────────
//  포맷: salt(16) || iv(12) || ciphertext+tag
async function encryptAES(plaintext, password, algorithm = 'argon2id') {
    if (algorithm === 'xor') return encryptXOR(plaintext, password);

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key  = await deriveKey(password, salt, algorithm);

    const cipherbuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        _enc_aes.encode(plaintext)
    );

    const out = new Uint8Array(SALT_LEN + IV_LEN + cipherbuf.byteLength);
    out.set(salt, 0);
    out.set(iv,   SALT_LEN);
    out.set(new Uint8Array(cipherbuf), SALT_LEN + IV_LEN);

    return btoa(String.fromCharCode(...out))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── 복호화 ─────────────────────────────────────
async function decryptAES(encoded, password, algorithm = 'argon2id') {
    if (algorithm === 'xor') return decryptXOR(encoded, password);

    const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - b64.length % 4) % 4;
    const raw = Uint8Array.from(atob(b64 + '='.repeat(pad)), c => c.charCodeAt(0));

    const salt       = raw.slice(0, SALT_LEN);
    const iv         = raw.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const ciphertext = raw.slice(SALT_LEN + IV_LEN);

    const key = await deriveKey(password, salt, algorithm);

    const plainbuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    return _dec_aes.decode(plainbuf);
}
