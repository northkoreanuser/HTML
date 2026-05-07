// ────────────────────────────────────────────────
//  argon2.js — Argon2id 키 파생
//  의존: argon2-browser CDN
// ────────────────────────────────────────────────

// OWASP 권장 파라미터
const ARGON2_MEM         = 65536; // 64MB
const ARGON2_TIME        = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASHLEN     = 32;    // 256-bit → AES-256 키

async function deriveKey_argon2id(password, salt) {
    const result = await argon2.hash({
        pass:        password,
        salt:        salt,
        type:        argon2.ArgonType.Argon2id,
        mem:         ARGON2_MEM,
        time:        ARGON2_TIME,
        parallelism: ARGON2_PARALLELISM,
        hashLen:     ARGON2_HASHLEN,
    });

    return crypto.subtle.importKey(
        'raw',
        result.hash,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}
