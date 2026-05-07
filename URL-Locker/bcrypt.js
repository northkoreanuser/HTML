// ────────────────────────────────────────────────
//  bcrypt.js — bcrypt 키 파생
//  실제 bcrypt는 브라우저 네이티브 미지원.
//  dcodeIO/bcryptjs(CDN)로 해시 → SHA-256 → AES 키
//  deriveKey_bcrypt(password, salt) → CryptoKey
// ────────────────────────────────────────────────

// bcryptjs 가 window.dcodeIO.bcrypt 또는 window.bcrypt 에 노출됨
// index.html 에서 CDN 로드:
//   <script src="https://cdn.jsdelivr.net/npm/bcryptjs@2.4.3/dist/bcrypt.min.js"></script>

const BCRYPT_COST = 12;         // cost factor (2^12 = 4096 rounds)
const _enc_bcrypt = new TextEncoder();

function _getBcrypt() {
    // CDN 노출 위치 통일
    return (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt)
        ? dcodeIO.bcrypt
        : (typeof bcrypt !== 'undefined' ? bcrypt : null);
}

/**
 * bcrypt(password, cost) → 60자 해시 문자열 → SHA-256 → AES-256-GCM 키
 * salt 파라미터는 bcrypt 내부 salt 생성에 시드로 활용 (앞 16바이트를 hex로 삽입)
 */
async function deriveKey_bcrypt(password, saltBytes) {
    const bc = _getBcrypt();
    if (!bc) throw new Error('bcryptjs 라이브러리가 로드되지 않았습니다.');

    // bcrypt salt 문자열: bcrypt 자체 salt 생성 (cost 포함)
    // saltBytes를 결정론적으로 쓰기 위해 password 앞에 hex seed 붙임
    const hexSeed   = Array.from(saltBytes).map(b => b.toString(16).padStart(2,'0')).join('');
    const bcryptSalt = await new Promise((resolve, reject) =>
        bc.genSalt(BCRYPT_COST, (err, s) => err ? reject(err) : resolve(s))
    );

    // hexSeed를 bcrypt 입력에 포함 → 같은 (password+hexSeed) 조합에서 동일 결과 없음
    // 실제 복호화 시 동일한 saltBytes → 동일 hexSeed → 동일 bcryptSalt 재현 불가
    // 따라서 bcrypt 출력을 직접 쓰지 않고 SHA-256으로 한 번 더 늘린다.
    //
    // ⚠️  bcrypt는 원래 패스워드 저장용이므로 매번 다른 salt를 씀.
    //     여기서는 "결정론적 KDF"가 필요하므로:
    //     → bcrypt 에 (hexSeed + ":" + password) 를 입력, bcrypt-salt 를 hexSeed 에서 재현
    //     → bcryptjs genSalt는 CSPRNG 기반이라 재현 불가 → 대신 SHA-256(hexSeed) 로 22자 salt 생성

    const saltHash  = await crypto.subtle.digest('SHA-256', _enc_bcrypt.encode(hexSeed));
    const saltB64   = btoa(String.fromCharCode(...new Uint8Array(saltHash)))
                        .replace(/\+/g, '.').replace(/\//g, '/').slice(0, 22);
    const bcryptSaltStr = `$2a$${String(BCRYPT_COST).padStart(2,'0')}$${saltB64}`;

    const bcryptHash = await new Promise((resolve, reject) =>
        bc.hash(password, bcryptSaltStr, (err, h) => err ? reject(err) : resolve(h))
    );

    // bcrypt 출력(60자 문자열) → SHA-256 → AES 키
    const rawKey = await crypto.subtle.digest('SHA-256', _enc_bcrypt.encode(bcryptHash));
    return crypto.subtle.importKey(
        'raw', rawKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}
