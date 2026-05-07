// ────────────────────────────────────────────────
//  xor.js — XOR 스트림 암호 (교육 목적)
//  ⚠️  보안 강도 낮음 — 실용 목적 비권장
//  encryptXOR(plaintext, password) → base64url string
//  decryptXOR(encoded,   password) → plaintext string
// ────────────────────────────────────────────────

const _enc_xor = new TextEncoder();
const _dec_xor = new TextDecoder();

/**
 * 키스트림: SHA-256(password || counter) 를 반복해 plaintext 길이만큼 생성
 * salt(16B) 포함 → 같은 password+plaintext 라도 매번 다른 출력
 */
async function _xorKeyStream(password, salt, length) {
    const pwBytes = _enc_xor.encode(password);
    const stream  = new Uint8Array(length);
    let   filled  = 0;
    let   counter = 0;

    while (filled < length) {
        const block = new Uint8Array(pwBytes.length + salt.length + 4);
        block.set(pwBytes, 0);
        block.set(salt, pwBytes.length);
        // counter (big-endian 4B)
        const view = new DataView(block.buffer, pwBytes.length + salt.length);
        view.setUint32(0, counter, false);

        const hash = new Uint8Array(
            await crypto.subtle.digest('SHA-256', block)
        );

        const take = Math.min(hash.length, length - filled);
        stream.set(hash.subarray(0, take), filled);
        filled  += take;
        counter += 1;
    }
    return stream;
}

async function encryptXOR(plaintext, password) {
    const salt      = crypto.getRandomValues(new Uint8Array(16));
    const plainBytes = _enc_xor.encode(plaintext);
    const keyStream  = await _xorKeyStream(password, salt, plainBytes.length);

    const cipher = new Uint8Array(16 + plainBytes.length);
    cipher.set(salt, 0);
    for (let i = 0; i < plainBytes.length; i++) {
        cipher[16 + i] = plainBytes[i] ^ keyStream[i];
    }

    return btoa(String.fromCharCode(...cipher))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function decryptXOR(encoded, password) {
    const b64  = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const pad  = (4 - b64.length % 4) % 4;
    const raw  = Uint8Array.from(atob(b64 + '='.repeat(pad)), c => c.charCodeAt(0));

    const salt        = raw.slice(0, 16);
    const cipherBytes = raw.slice(16);
    const keyStream   = await _xorKeyStream(password, salt, cipherBytes.length);

    const plainBytes = new Uint8Array(cipherBytes.length);
    for (let i = 0; i < cipherBytes.length; i++) {
        plainBytes[i] = cipherBytes[i] ^ keyStream[i];
    }
    return _dec_xor.decode(plainBytes);
}
