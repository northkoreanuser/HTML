// ────────────────────────────────────────────────
//  app.js — UI / 앱 로직
//  알고리즘: argon2id | pbkdf2 | bcrypt | xor
//  URL 파라미터: ?hash=...&algorithm=argon2id&hint=...
// ────────────────────────────────────────────────

const FALLBACK_URL = 'https://youtu.be/EWjw8MSmKi4?t=0';

let _encryptedUrl  = '';
let _savedHash     = null;
let _savedAlgo     = 'argon2id';
let _failCount     = 0;
let _blasting      = false;

// 알고리즘 메타 정보
const ALGO_META = {
    argon2id: {
        label:      'Argon2id',
        badge:      'AES-256-GCM · Argon2id',
        kdfInfo:    '키는 <strong>Argon2id</strong>으로 파생 — 브루트포스 저항',
        spinner:    'Argon2id 처리 중...',
        security:   5,
        warn:       null,
    },
    pbkdf2: {
        label:      'PBKDF2',
        badge:      'AES-256-GCM · PBKDF2 · 600K',
        kdfInfo:    '키는 <strong>PBKDF2-SHA256 × 600,000</strong>으로 파생 — 브루트포스 저항',
        spinner:    'PBKDF2 · 600,000 iterations...',
        security:   3,
        warn:       null,
    },
    bcrypt: {
        label:      'bcrypt',
        badge:      'AES-256-GCM · bcrypt (cost 12)',
        kdfInfo:    '키는 <strong>bcrypt cost=12</strong>으로 파생',
        spinner:    'bcrypt 처리 중 (cost 12)...',
        security:   4,
        warn:       null,
    },
    xor: {
        label:      'XOR',
        badge:      'XOR 스트림 암호',
        kdfInfo:    '⚠️ <strong>XOR</strong>은 보안 강도가 낮습니다 — 교육 목적에만 사용',
        spinner:    'XOR 처리 중...',
        security:   1,
        warn:       '⚠️ XOR은 보안 강도가 낮습니다. 민감한 URL에는 사용하지 마세요.',
    },
};

// ── 추방 ───────────────────────────────────────
function _blastOff() {
    if (_blasting) return;
    _blasting = true;
    history.replaceState(null, '', window.location.pathname);
    window.location.replace(FALLBACK_URL);
}

// ── 보안 리스너 ────────────────────────────────
function _attachSecurityListeners() {
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) _blastOff();
    });
    window.addEventListener('blur', () => _blastOff());
    document.addEventListener('contextmenu', e => {
        e.preventDefault(); e.stopPropagation(); _blastOff();
    });
    document.addEventListener('keydown', e => {
        const c    = e.key.toUpperCase();
        const ctrl = e.ctrlKey || e.metaKey;
        if (e.key === 'F12')                                          { e.preventDefault(); _blastOff(); return; }
        if (ctrl && e.shiftKey && ['I','J','C','K','E'].includes(c)) { e.preventDefault(); _blastOff(); return; }
        if (ctrl && ['U','S','P'].includes(c))                       { e.preventDefault(); _blastOff(); return; }
        if (ctrl && ['A','F'].includes(c))                           { e.preventDefault(); return; }
        if (e.key === 'F6')                                          { e.preventDefault(); _blastOff(); return; }
    }, true);
    document.addEventListener('selectstart', e => e.preventDefault());
    document.addEventListener('dragstart',   e => e.preventDefault());

    const _devtoolsCheck = setInterval(() => {
        if (window.outerWidth  - window.innerWidth  > 160 ||
            window.outerHeight - window.innerHeight > 160) {
            clearInterval(_devtoolsCheck); _blastOff();
        }
    }, 500);

    (function _devtoolsTiming() {
        const start = performance.now();
        debugger; // eslint-disable-line no-debugger
        if (performance.now() - start > 100) { _blastOff(); return; }
        setTimeout(_devtoolsTiming, 1000);
    })();
}

// ── 알고리즘 선택기 업데이트 ───────────────────
function _getSelectedAlgo() {
    return document.getElementById('algoSelect')?.value || 'argon2id';
}

function _updateAlgoUI(algo) {
    const meta = ALGO_META[algo] || ALGO_META['argon2id'];

    // 뱃지
    const badge = document.querySelector('#encryptSection .security-badge');
    if (badge) badge.childNodes[badge.childNodes.length - 1].textContent = ' ' + meta.badge;

    // kdf-info
    const kdfInfo = document.querySelector('.kdf-info span:last-child');
    if (kdfInfo) kdfInfo.innerHTML = meta.kdfInfo;

    // spinner label
    const kdfProg = document.querySelector('#encryptSection .kdf-progress');
    if (kdfProg) kdfProg.textContent = meta.spinner;

    // 경고 박스
    let warnBox = document.getElementById('algoWarnBox');
    if (meta.warn) {
        if (!warnBox) {
            warnBox = document.createElement('div');
            warnBox.id = 'algoWarnBox';
            warnBox.style.cssText = 'margin-bottom:16px;padding:10px 14px;background:rgba(255,79,106,0.1);border:1px solid rgba(255,79,106,0.4);border-radius:8px;font-size:0.7rem;color:#ff4f6a;letter-spacing:0.04em;';
            const kdfEl = document.querySelector('.kdf-info');
            kdfEl.parentNode.insertBefore(warnBox, kdfEl);
        }
        warnBox.textContent = meta.warn;
        warnBox.style.display = 'block';
    } else if (warnBox) {
        warnBox.style.display = 'none';
    }

    // 보안 레벨 표시 업데이트
    const secBar = document.getElementById('securityLevel');
    if (secBar) {
        secBar.querySelectorAll('.sec-seg').forEach((seg, i) => {
            seg.style.background = i < meta.security
                ? (meta.security <= 1 ? '#ff4f6a' : meta.security <= 2 ? '#ff9f4f' : meta.security <= 3 ? '#ffe04f' : '#4fffb0')
                : 'var(--border)';
        });
    }
}

// ── 암호화 UI ──────────────────────────────────
async function handleEncrypt() {
    const url  = document.getElementById('urlInput').value.trim();
    const key  = document.getElementById('keyInput').value;
    const algo = _getSelectedAlgo();

    if (!url || !key) { alert('URL과 KEY를 모두 입력하세요.'); return; }
    if (!isValidUrl(url)) { alert('올바른 URL 형식을 입력하세요.'); return; }

    setEncryptLoading(true);
    try {
        const hash = await encryptAES(url, key, algo);
        const hint = document.getElementById('hintInput').value.trim();
        const base = window.location.href.split('?')[0];
        _encryptedUrl = `${base}?hash=${hash}&algorithm=${algo}`
            + (hint ? `&hint=${encodeURIComponent(hint)}` : '');

        document.getElementById('encryptSection').style.display = 'none';
        document.getElementById('resultSection').style.display  = 'block';
        document.getElementById('encryptedUrlDisplay').innerHTML =
            `<a href="${_encryptedUrl}" target="_blank" rel="noopener noreferrer">${_encryptedUrl}</a>`;

        QRCode.toDataURL(_encryptedUrl, { errorCorrectionLevel: 'H', width: 180 }, (err, dataUrl) => {
            if (!err) document.getElementById('qrcode').src = dataUrl;
        });
    } catch (e) {
        console.error(e);
        alert('암호화 중 오류가 발생했습니다: ' + (e.message || e));
    }
    setEncryptLoading(false);
}

function setEncryptLoading(on) {
    document.getElementById('lockBtn').style.display = on ? 'none' : 'block';
    document.getElementById('encryptSpinner').classList.toggle('active', on);
}

// ── 복호화 UI ──────────────────────────────────
async function handleDecrypt() {
    const key  = document.getElementById('decryptKeyInput').value;
    const algo = document.getElementById('decryptAlgoSelect')?.value || _savedAlgo;
    if (!key || !_savedHash) return;

    setDecryptLoading(true);
    const keyInput = document.getElementById('decryptKeyInput');
    keyInput.classList.remove('error');

    try {
        const decrypted = await decryptAES(_savedHash, key, algo);
        history.replaceState(null, '', window.location.pathname);
        window.location.replace(decrypted);
    } catch (e) {
        _failCount++;
        if (_failCount >= 1) { _blastOff(); return; }
        keyInput.classList.add('error');
        keyInput.classList.remove('shake');
        void keyInput.offsetWidth;
        keyInput.classList.add('shake');
        keyInput.value = '';
        setTimeout(() => keyInput.classList.remove('error'), 1500);
    }
    setDecryptLoading(false);
}

function setDecryptLoading(on) {
    document.getElementById('unlockBtn').style.display = on ? 'none' : 'block';
    document.getElementById('decryptSpinner').classList.toggle('active', on);
}

// ── 기타 UI 헬퍼 ───────────────────────────────
function copyEncrypted() {
    navigator.clipboard.writeText(_encryptedUrl).then(() => {
        flashBtn(event.target, '✅ 복사됨');
    });
}

function downloadQR() {
    const img = document.getElementById('qrcode');
    if (!img.src) return;
    const a = document.createElement('a');
    a.href = img.src;
    a.download = 'url-locker-qr.png';
    a.click();
}

function resetAll() {
    document.getElementById('resultSection').style.display  = 'none';
    document.getElementById('encryptSection').style.display = 'block';
    document.getElementById('urlInput').value    = '';
    document.getElementById('keyInput').value    = '';
    document.getElementById('hintInput').value   = '';
    document.getElementById('strengthBar').className = 'strength-bar';
    document.getElementById('strengthLabel').textContent = '';
    _encryptedUrl = '';
}

function toggleVis(inputId, btn) {
    const input = document.getElementById(inputId);
    const isText = input.type === 'text';
    input.type = isText ? 'password' : 'text';
    btn.textContent = isText ? '👁' : '🙈';
}

function flashBtn(btn, label) {
    const orig = btn.textContent;
    btn.textContent = label;
    setTimeout(() => { btn.textContent = orig; }, 1500);
}

function isValidUrl(str) {
    try { return ['http:', 'https:'].includes(new URL(str).protocol); }
    catch { return false; }
}

// ── 비밀번호 강도 ──────────────────────────────
function calcStrength(pw) {
    if (!pw) return 0;
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 14) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(score, 4);
}

const STRENGTH_LABELS = ['', '취약', '보통', '양호', '강함'];

document.getElementById('keyInput').addEventListener('input', function () {
    const s   = calcStrength(this.value);
    const bar = document.getElementById('strengthBar');
    const lbl = document.getElementById('strengthLabel');
    bar.className   = 'strength-bar' + (s ? ` s${s}` : '');
    lbl.textContent = this.value ? STRENGTH_LABELS[s] : '';
});

document.getElementById('algoSelect')?.addEventListener('change', function () {
    _updateAlgoUI(this.value);
});

// ── 엔터 키 ────────────────────────────────────
['urlInput', 'keyInput'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); handleEncrypt(); }
    });
});
document.getElementById('decryptKeyInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); handleDecrypt(); }
});

// ── fmt 렌더링 ─────────────────────────────────
// fmt=1 → {title}\n{url}
// fmt=2 → [{title}]({url})
// fmt=3 → <a href="{url}">{title}</a>
// fmt=N(커스텀) → 파라미터 fmtTpl 에 템플릿 문자열
function _renderFmt(fmt, fmtTpl, title, url) {
    if (fmtTpl) {
        // 커스텀 템플릿: {title}, {url} 치환
        return fmtTpl.replace(/\{title\}/g, title).replace(/\{url\}/g, url);
    }
    switch (fmt) {
        case '2': return `[${title}](${url})`;
        case '3': return `<a href="${url}">${title}</a>`;
        case '4': return `<a href="${url}"><img src="🔐" alt="${title}"></a>`;
        default:  return title ? `${title}\n${url}` : url;
    }
}

// ── 자동 암호화 (lock=1&url=...&pw=...) ────────
async function handleAutoEncrypt(params) {
    const autoUrl    = params.get('url');
    const autoPw     = params.get('pw');
    const autoHint   = params.get('hint');
    const autoFmt    = params.get('fmt');
    const autoFmtTpl = params.get('fmtTpl');   // 커스텀 템플릿
    const autoTitle  = params.get('title') || '';
    const autoAlgo   = params.get('algorithm') || 'argon2id';
    const base       = window.location.href.split('?')[0];

    history.replaceState(null, '', '?lock=1');
    document.getElementById('encryptSection').style.display = 'none';

    const spinEl = document.getElementById('encryptSpinner');
    spinEl.style.display = 'flex';
    spinEl.classList.add('active');

    try {
        const hash = await encryptAES(autoUrl, autoPw, autoAlgo);
        _encryptedUrl = `${base}?hash=${hash}&algorithm=${autoAlgo}`
            + (autoHint ? '&hint=' + encodeURIComponent(autoHint) : '');

        spinEl.classList.remove('active');
        spinEl.style.display = 'none';

        document.getElementById('resultSection').style.display = 'block';
        document.getElementById('encryptedUrlDisplay').innerHTML =
            `<a href="${_encryptedUrl}" target="_blank" rel="noopener noreferrer">${_encryptedUrl}</a>`;

        // fmt 있으면 포맷 적용, 없으면 암호화된 URL 그대로 복사
        const fmtOutput = (autoFmt || autoFmtTpl)
            ? _renderFmt(autoFmt, autoFmtTpl, autoTitle, _encryptedUrl)
            : _encryptedUrl;

        // 복사 시도 → 성공하면 탭 닫기 바 표시, 실패하면 수동 복사 UI
        navigator.clipboard.writeText(fmtOutput).then(() => {
            _showAutoCloseBar(true, fmtOutput);
            setTimeout(() => { if (!window.closed) window.close(); }, 1500);
        }).catch(() => {
            _showFmtFallback(autoFmt, autoFmtTpl, autoTitle, fmtOutput);
            _showAutoCloseBar(false, fmtOutput);
        });

        QRCode.toDataURL(_encryptedUrl, { errorCorrectionLevel: 'H', width: 180 }, (err, dataUrl) => {
            if (!err) document.getElementById('qrcode').src = dataUrl;
        });

    } catch (err) {
        spinEl.classList.remove('active');
        spinEl.style.display = 'none';
        alert('자동 암호화 중 오류가 발생했습니다: ' + (err.message || err));
        history.replaceState(null, '', '?lock=1');
        document.getElementById('encryptSection').style.display = 'block';
    }
}

// ── 자동 닫기 바 ───────────────────────────────
// copied=true: 복사 성공 → 카운트다운 후 탭 닫기 시도
// copied=false: 복사 실패 → 닫기 버튼만 표시
function _showAutoCloseBar(copied, fmtOutput) {
    const bar = document.createElement('div');
    bar.id = 'autoCloseBar';
    bar.style.cssText = [
        'margin-top:16px',
        'padding:12px 16px',
        'border-radius:10px',
        'font-size:0.72rem',
        'display:flex',
        'align-items:center',
        'justify-content:space-between',
        'gap:12px',
        copied
            ? 'background:var(--accent-dim);border:1px solid rgba(79,255,176,0.35);color:var(--accent)'
            : 'background:var(--surface2);border:1px solid var(--border);color:var(--text-dim)',
    ].join(';');

    const msg  = document.createElement('span');
    const btn  = document.createElement('button');
    btn.className = 'btn-secondary';
    btn.style.cssText = 'flex:none;padding:7px 14px;font-size:0.72rem';

    if (copied) {
        let sec = 1;
        msg.textContent = `✅ 복사됨 — ${sec}초 후 탭 닫기`;
        btn.textContent = '✕ 닫기';
        btn.onclick = () => window.close();

        const iv = setInterval(() => {
            sec--;
            if (sec <= 0) { clearInterval(iv); return; }
            msg.textContent = `✅ 복사됨 — ${sec}초 후 탭 닫기`;
        }, 1000);
    } else {
        msg.textContent = '⚠️ 클립보드 권한 없음 — 수동으로 복사하세요';
        btn.textContent = '✕ 탭 닫기';
        btn.onclick = () => window.close();
    }

    bar.appendChild(msg);
    bar.appendChild(btn);
    document.getElementById('resultSection').appendChild(bar);
}

function _showFmtFallback(autoFmt, autoFmtTpl, autoTitle, fmtOutput) {
    const fmtLabel = autoFmtTpl  ? '🛠 커스텀 템플릿'
        : autoFmt === '2'        ? '📝 마크다운'
        : autoFmt === '3'        ? '🏷 링크 태그'
        :                          '📄 일반 (제목 + URL)';

    const fmtCard = document.createElement('div');
    fmtCard.className = 'result-card';
    fmtCard.style.marginTop = '16px';
    fmtCard.innerHTML = `
        <div class="result-label">${fmtLabel}</div>
        <div class="result-url" style="cursor:pointer;user-select:all;">${fmtOutput.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
        <div class="btn-row" style="margin-top:12px;">
            <button class="btn-secondary" id="fmtCopyBtn">📋 복사</button>
        </div>`;
    document.getElementById('resultSection').appendChild(fmtCard);
    document.getElementById('fmtCopyBtn').onclick = () => {
        navigator.clipboard.writeText(fmtOutput).then(() => {
            flashBtn(document.getElementById('fmtCopyBtn'), '✅ 복사됨');
            setTimeout(() => window.close(), 800);
        });
    };
}

// ── 초기화: 모드 감지 ──────────────────────────
(function init() {
    const params = new URLSearchParams(window.location.search);
    const hash   = params.get('hash');
    const hint   = params.get('hint');
    const marker = params.get('v');
    const lock   = params.get('lock');
    const algo   = params.get('algorithm') || 'argon2id';

    // F5 감지 — 마커 있으면 추방
    if (marker === '1') {
        history.replaceState(null, '', window.location.pathname);
        window.location.replace(FALLBACK_URL);
        return;
    }

    // ── 복호화 모드 ──────────────────────────────
    if (hash) {
        _savedHash = hash;
        _savedAlgo = algo;
        history.replaceState(null, '', '?v=1');

        document.getElementById('decryptSection').style.display = 'block';
        document.title = 'URL LOCKED 🔐';
        document.querySelector('.logo').innerHTML  = 'URL<span>LOCKED</span> 🔐';
        document.querySelector('.subtitle').textContent = 'Decrypt & access your URL';

        // 알고리즘 선택기 초기값 설정
        const algoSel = document.getElementById('decryptAlgoSelect');
        if (algoSel) {
            algoSel.value = algo;
            // 파라미터로 알고리즘이 확정된 경우 선택기 숨김(자동)
            const algoField = document.getElementById('decryptAlgoField');
            if (algoField) {
                // 파라미터가 명시됐으면 자동 감지 배지 표시
                const autoNote = document.getElementById('algoAutoNote');
                if (autoNote) {
                    autoNote.textContent = `알고리즘 자동 감지: ${(ALGO_META[algo]||{}).label || algo}`;
                    autoNote.style.display = 'block';
                }
            }
        }

        if (hint) {
            document.getElementById('hintBox').style.display = 'block';
            document.getElementById('hintText').textContent  = hint;
        }

        _attachSecurityListeners();
        return;
    }

    // ── 잠금 모드 ────────────────────────────────
    if (lock === '1') {
        const autoUrl = params.get('url');
        const autoPw  = params.get('pw');

        if (autoUrl && autoPw) {
            handleAutoEncrypt(params);
        } else {
            history.replaceState(null, '', '?lock=1');
            document.getElementById('encryptSection').style.display = 'block';
            // 초기 algo UI 반영
            _updateAlgoUI(_getSelectedAlgo());
        }
        return;
    }

    // ── 파라미터 없음 → 추방 ─────────────────────
    _blastOff();
})();
