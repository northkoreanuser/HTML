// ==UserScript==
// @name          다기능 컨텍스트 메뉴
// @namespace     다기능 컨텍스트 메뉴
// @version       0.30
// @description   컨텍스트 메뉴 + 스크롤 북마크 + 위치 기억 + 페이지 메모(AES-256 자체 암호화) + ContextData AES-256 통합 + 보안 복사 Argon2id/PBKDF2 병행 선택 + WASM CSP 자동 감지
// @match         *://*/*
// @icon          https://www.svgrepo.com/show/294189/script.svg
// @author        mickey90427 <mickey90427@naver.com>
// @license       MIT
// @run-at        document-end
// @grant         GM_getValue
// @grant         GM_setValue
// @grant         GM_deleteValue
// @grant         GM_listValues
// @require       https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js
// ==/UserScript==

(function () {
    'use strict';

    // ── 공통 헬퍼 ──────────────────────────────────────────────
    const el  = (tag, p = {}) => Object.assign(document.createElement(tag), p);
    const css = (e, s) => Object.assign(e.style, s);

    // ── 보안 URL 복사: Argon2id + AES-256-GCM / PBKDF2 + AES-256-GCM ──
    const SECURE_URL_BASE_ARGON2  = 'https://northkoreanuser.github.io/HTML/URL-Locker/Argon2.html';
    const SECURE_URL_BASE_PBKDF2  = 'https://northkoreanuser.github.io/HTML/URL-Locker/PBKDF2.html';
    const SU_SALT_LEN             = 16;
    const SU_IV_LEN               = 12;

    // ── Argon2id 파라미터 ──────────────────────────────────────
    const SU_ARGON2_MEM     = 65536; // 64MB — OWASP 권장
    const SU_ARGON2_TIME    = 3;
    const SU_ARGON2_PAR     = 1;
    const SU_ARGON2_HASHLEN = 32;    // 256-bit → AES-256 키

    // ── PBKDF2 파라미터 ────────────────────────────────────────
    const SU_PBKDF2_ITERATIONS = 600_000; // PBKDF2.html 과 동일

    // ── Argon2id 키 파생 ───────────────────────────────────────
    async function _suDeriveArgon2(password, salt) {
        const result = await argon2.hash({
            pass:        password,
            salt:        salt,
            type:        argon2.ArgonType.Argon2id,
            mem:         SU_ARGON2_MEM,
            time:        SU_ARGON2_TIME,
            parallelism: SU_ARGON2_PAR,
            hashLen:     SU_ARGON2_HASHLEN,
        });
        return crypto.subtle.importKey(
            'raw',
            result.hash,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // ── PBKDF2-SHA256 키 파생 ──────────────────────────────────
    async function _suDerivePBKDF2(password, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: SU_PBKDF2_ITERATIONS, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // 포맷: salt(16) || iv(12) || ciphertext+GCM-tag  →  base64url
    async function _suEncryptWith(plaintext, password, deriveFn) {
        const salt = crypto.getRandomValues(new Uint8Array(SU_SALT_LEN));
        const iv   = crypto.getRandomValues(new Uint8Array(SU_IV_LEN));
        const key  = await deriveFn(password, salt);
        const ct   = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            new TextEncoder().encode(plaintext)
        );
        const out = new Uint8Array(SU_SALT_LEN + SU_IV_LEN + ct.byteLength);
        out.set(salt, 0);
        out.set(iv,   SU_SALT_LEN);
        out.set(new Uint8Array(ct), SU_SALT_LEN + SU_IV_LEN);
        return btoa(String.fromCharCode(...out))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // 편의 래퍼
    const _suEncryptArgon2  = (pt, pw) => _suEncryptWith(pt, pw, _suDeriveArgon2);
    const _suEncryptPBKDF2  = (pt, pw) => _suEncryptWith(pt, pw, _suDerivePBKDF2);

    // ── WASM 가용성 감지 (CSP 차단 여부 판별) ─────────────────
    // 최소 유효 WASM 모듈(8바이트 magic+version)을 컴파일 시도.
    // 'wasm-unsafe-eval' 없는 CSP 환경(GitHub 등)에선 즉시 reject.
    let _wasmAllowed = null; // null=미확인, true/false=캐시
    async function _checkWasmAllowed() {
        if (_wasmAllowed !== null) return _wasmAllowed;
        try {
            await WebAssembly.compile(new Uint8Array([0,97,115,109,1,0,0,0]));
            _wasmAllowed = true;
        } catch {
            _wasmAllowed = false;
        }
        return _wasmAllowed;
    }

    // 보안 URL 복사 모달: 비밀번호 + 선택적 힌트 입력 → 암호화 → 클립보드
    // format: 'plain' | 'markdown' | 'tag'
    async function showSecureUrlCopyModal(format = 'plain') {
        const targetUrl = decodeURIComponent(location.href);
        const pageTitle = document.title;
        const FORMAT_LABEL = { plain:'일반 (제목 + URL)', markdown:'마크다운', tag:'링크 태그' };
        const buildOutput = (lockedUrl) => {
            if (format === 'markdown') return `[${pageTitle}](${lockedUrl})`;
            if (format === 'tag')      return `<a href="${lockedUrl}">${pageTitle}</a>`;
            return `${pageTitle}\n${lockedUrl}`; // plain
        };

        const { ov, append } = mkModal(360, '#111518');

        // 현재 선택 알고리즘 상태
        let selectedAlgo = 'argon2'; // 'argon2' | 'pbkdf2'

        // 제목
        const title = el('div');
        title.innerHTML = `🔐 <strong>보안 URL 복사</strong> <span style="font-size:10px;color:#555;font-weight:normal">· ${FORMAT_LABEL[format]}</span>`;
        css(title, { fontSize:'14px', color:'#4fffb0', marginBottom:'6px', fontFamily:'monospace' });

        // ── 알고리즘 선택 토글 ────────────────────────────────
        const algoWrap = el('div');
        css(algoWrap, { display:'flex', gap:'6px', marginBottom:'10px' });

        const ALGO_CFG = {
            argon2: {
                label : 'Argon2id',
                desc  : 'Argon2id → AES-256-GCM 으로 현재 URL을 암호화합니다.\n힌트는 평문으로 저장됩니다.',
                kdf   : '🛡 키는 <span style="color:#4fffb0">Argon2id</span> (mem=64MB, t=3) 으로 파생 — 메모리 하드 저항',
                loading: '<span style="color:#4fffb0">⏳</span> Argon2id 키 파생 중... (수 초 소요)',
                base  : SECURE_URL_BASE_ARGON2,
                encrypt: _suEncryptArgon2,
            },
            pbkdf2: {
                label : 'PBKDF2',
                desc  : 'PBKDF2-SHA256 × 600,000 → AES-256-GCM 으로 현재 URL을 암호화합니다.\n힌트는 평문으로 저장됩니다.',
                kdf   : '🛡 키는 <span style="color:#4fffb0">PBKDF2-SHA256 × 600,000</span> 으로 파생 — 브루트포스 저항',
                loading: '<span style="color:#4fffb0">⏳</span> PBKDF2 키 파생 중... (잠시 소요)',
                base  : SECURE_URL_BASE_PBKDF2,
                encrypt: _suEncryptPBKDF2,
            },
        };

        const makeAlgoBtn = (algoKey) => {
            const cfg = ALGO_CFG[algoKey];
            const btn = el('button', { type:'button', textContent: cfg.label });
            css(btn, {
                flex: '1', padding: '6px 0', borderRadius: '6px', fontSize: '12px',
                fontFamily: 'monospace', cursor: 'pointer', transition: 'all .15s',
                border: '1px solid #2a2f42', background: '#161920', color: '#888',
            });
            btn._algoKey = algoKey;
            return btn;
        };

        const algoButtons = {};
        ['argon2', 'pbkdf2'].forEach(k => {
            const btn = makeAlgoBtn(k);
            algoButtons[k] = btn;
            algoWrap.appendChild(btn);
        });

        const updateAlgoUI = () => {
            Object.entries(algoButtons).forEach(([k, btn]) => {
                const active = k === selectedAlgo;
                btn.style.background = active ? '#1a3d2e' : '#161920';
                btn.style.color      = active ? '#4fffb0' : '#888';
                btn.style.border     = active ? '1px solid rgba(79,255,176,0.4)' : '1px solid #2a2f42';
                btn.style.fontWeight = active ? 'bold' : 'normal';
            });
            // desc / kdfInfo / loadEl 동기화
            desc.textContent    = ALGO_CFG[selectedAlgo].desc;
            kdfInfo.innerHTML   = ALGO_CFG[selectedAlgo].kdf;
            loadEl.innerHTML    = ALGO_CFG[selectedAlgo].loading;
        };

        Object.entries(algoButtons).forEach(([k, btn]) => {
            btn.onclick = () => { selectedAlgo = k; updateAlgoUI(); };
        });

        // 설명 (초기값은 argon2)
        const desc = el('div', { textContent: ALGO_CFG['argon2'].desc });
        css(desc, { fontSize:'11px', color:'#666', marginBottom:'14px', whiteSpace:'pre-line', lineHeight:'1.6' });

        // URL 미리보기
        const urlPrev = el('div');
        urlPrev.textContent = targetUrl.length > 60 ? targetUrl.slice(0, 57) + '…' : targetUrl;
        css(urlPrev, { fontSize:'10px', color:'#4fffb0', background:'#0d1a0f', border:'1px solid #1a3d2e',
                       borderRadius:'6px', padding:'7px 10px', marginBottom:'14px',
                       wordBreak:'break-all', lineHeight:'1.5', fontFamily:'monospace' });

        // 비밀번호 입력
        const pwWrap = el('div'); css(pwWrap, { position:'relative', marginBottom:'4px' });
        const pwInput = el('input', { type:'password', placeholder:'암호화 키 입력', maxLength:256 });
        css(pwInput, { ...iCSS, paddingRight:'38px', marginBottom:'0' });
        const eyeBtn = el('button', { type:'button', textContent:'👁' });
        css(eyeBtn, { position:'absolute', right:'8px', top:'50%', transform:'translateY(-50%)',
                      background:'none', border:'none', cursor:'pointer', fontSize:'14px',
                      color:'#888', padding:'0', lineHeight:'1' });
        eyeBtn.onclick = () => {
            pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
            eyeBtn.textContent = pwInput.type === 'password' ? '👁' : '🙈';
        };
        pwWrap.append(pwInput, eyeBtn);

        // 강도 바
        const strengthWrap = el('div');
        css(strengthWrap, { display:'flex', gap:'3px', margin:'6px 0 2px' });
        const segs = Array.from({ length: 4 }, () => {
            const s = el('div'); css(s, { flex:'1', height:'3px', background:'#2a2f42', borderRadius:'2px', transition:'background .3s' }); return s;
        });
        segs.forEach(s => strengthWrap.appendChild(s));
        const strengthLbl = el('div'); css(strengthLbl, { fontSize:'10px', color:'#888', marginBottom:'10px', letterSpacing:'0.08em' });

        const calcStrength = pw => {
            if (!pw) return 0;
            let s = 0;
            if (pw.length >= 8)  s++;
            if (pw.length >= 14) s++;
            if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
            if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++;
            return Math.min(s, 4);
        };
        const strColors = ['','#ff4f6a','#ff9f4f','#ffe04f','#4fffb0'];
        const strLabels = ['','취약','보통','양호','강함'];
        pwInput.addEventListener('input', () => {
            const s = calcStrength(pwInput.value);
            segs.forEach((seg, i) => { seg.style.background = i < s ? strColors[s] : '#2a2f42'; });
            strengthLbl.textContent = pwInput.value ? strLabels[s] : '';
        });

        // 힌트 입력
        const hintInput = el('input', { type:'text', placeholder:'힌트 (선택사항 · 평문 저장)', maxLength:200 });
        css(hintInput, { ...iCSS });

        // KDF 안내 (동적 — updateAlgoUI() 에서 갱신)
        const kdfInfo = el('div');
        kdfInfo.innerHTML = ALGO_CFG['argon2'].kdf;
        css(kdfInfo, { fontSize:'11px', color:'#555', background:'#161920', border:'1px solid #2a2f42',
                       borderRadius:'6px', padding:'8px 12px', marginBottom:'14px', fontFamily:'monospace' });

        // 에러
        const errEl = el('div'); css(errEl, { fontSize:'11px', color:'#ff4f6a', minHeight:'16px', marginBottom:'8px' });

        // 로딩 상태 (동적 — updateAlgoUI() 에서 갱신)
        const loadEl = el('div');
        loadEl.innerHTML = ALGO_CFG['argon2'].loading;
        css(loadEl, { fontSize:'11px', color:'#888', display:'none', textAlign:'center', padding:'8px 0', fontFamily:'monospace' });

        const close = () => ov.remove();

        const doEncrypt = async () => {
            const pw   = pwInput.value;
            const hint = hintInput.value.trim();
            if (!pw || pw.length < 1) { errEl.textContent = '암호화 키를 입력하세요'; return; }

            // WASM 차단 + Argon2id 탭 → 암호화 시도 없이 Argon2.html 새 탭으로 위임
            if (selectedAlgo === 'argon2' && _wasmAllowed === false) {
                const fmtNum = format === 'markdown' ? '2' : format === 'tag' ? '3' : '1';
                const delegateUrl = SECURE_URL_BASE_ARGON2
                    + '?lock=1'
                    + '&url=' + encodeURIComponent(targetUrl)
                    + '&pw='  + encodeURIComponent(pw)
                    + (hint ? '&hint=' + encodeURIComponent(hint) : '')
                    + '&title=' + encodeURIComponent(pageTitle)
                    + '&fmt='  + fmtNum;
                window.open(delegateUrl, '_blank', 'noopener,noreferrer');
                ov.remove();
                return;
            }

            // 버튼 비활성화, 로딩 표시
            confirmBtn.disabled = true;
            cancelBtn.disabled  = true;
            loadEl.style.display = 'block';
            errEl.textContent = '';

            try {
                const cfg        = ALGO_CFG[selectedAlgo];
                const hash       = await cfg.encrypt(targetUrl, pw);
                const lockedUrl  = cfg.base
                    + '?hash=' + hash
                    + (hint ? '&hint=' + encodeURIComponent(hint) : '');
                const output = buildOutput(lockedUrl);

                await (navigator.clipboard?.writeText(output).catch(() => {
                    const x = el('textarea', { value: output });
                    css(x, { position:'fixed', opacity:'0' });
                    document.body.appendChild(x); x.select();
                    document.execCommand('copy'); x.remove();
                }) ?? (() => {
                    const x = el('textarea', { value: output });
                    css(x, { position:'fixed', opacity:'0' });
                    document.body.appendChild(x); x.select();
                    document.execCommand('copy'); x.remove();
                })());

                ov.remove();

                // 성공 토스트
                const algoLabel = selectedAlgo === 'pbkdf2' ? 'PBKDF2' : 'Argon2id';
                const toast2 = el('div', { textContent: `✅ 보안 URL 복사됨 [${algoLabel}] (${FORMAT_LABEL[format]})` });
                css(toast2, { position:'fixed', top:'50%', left:'50%', transform:'translate(-50%,-50%)',
                              padding:'12px 20px', background:'#0d1a0f', color:'#4fffb0',
                              border:'1px solid #1a3d2e', borderRadius:'10px',
                              fontFamily:'monospace', fontSize:'13px', zIndex:'2147483647',
                              pointerEvents:'none', boxShadow:'0 4px 24px rgba(0,0,0,.5)' });
                document.body.appendChild(toast2);
                setTimeout(() => toast2.remove(), 2200);

            } catch (e) {
                errEl.textContent = '암호화 중 오류: ' + (e.message || e);
                confirmBtn.disabled = false;
                cancelBtn.disabled  = false;
                loadEl.style.display = 'none';
            }
        };

        const confirmBtn = mkBtn('🔐 암호화 & 복사', '#1a3d2e', doEncrypt);
        css(confirmBtn, { color:'#4fffb0', border:'1px solid rgba(79,255,176,0.4)', flex:'1', fontSize:'12px' });
        const cancelBtn  = mkBtn('취소', '#222', close);
        css(cancelBtn, { border:'1px solid #333', fontSize:'12px' });

        [pwInput, hintInput].forEach(inp => inp.addEventListener('keydown', e => {
            if (e.key === 'Enter') doEncrypt();
            if (e.key === 'Escape') close();
        }));

        const btnRow = el('div');
        css(btnRow, { display:'flex', gap:'6px', justifyContent:'flex-end' });
        btnRow.append(confirmBtn, cancelBtn);

        append(title, algoWrap, desc, urlPrev, pwWrap, strengthWrap, strengthLbl, hintInput, kdfInfo, errEl, loadEl, btnRow);
        updateAlgoUI(); // 초기 상태 렌더링
        pwInput.focus();

        // ── WASM 가용성 확인 후 안내 메시지 표시 ────────────────
        // 실제 위임 로직은 doEncrypt() 내부에서 _wasmAllowed===false 감지 시 처리
        _checkWasmAllowed().then(ok => {
            if (ok) return; // 정상 — 변경 없음

            // 안내 메시지 표시
            const cspNote = el('div');
            cspNote.textContent = '이 페이지의 CSP 제한으로 Argon2id는 새 탭(URL Locker)에서 처리됩니다. WASM 제약이 없는 환경에서 동일하게 암호화됩니다.';
            css(cspNote, { fontSize:'10px', color:'#4fffb0', background:'#0d1a0f',
                           border:'1px solid #1a3d2e', borderRadius:'6px',
                           padding:'6px 10px', marginTop:'6px', lineHeight:'1.5', fontFamily:'monospace' });
            algoWrap.insertAdjacentElement('afterend', cspNote);
        });
    }

    // ── GM 스토리지 래퍼 ───────────────────────────────────────
    const gmGet  = (k, d = null) => { try { return GM_getValue(k, d); } catch { return d; } };
    const gmSet  = (k, v)        => { try { GM_setValue(k, v); }       catch {} };
    const gmDel  = (k)           => { try { GM_deleteValue(k); }       catch {} };
    const gmKeys = ()            => { try { return GM_listValues(); }   catch { return []; } };

    // ── 스토리지 키/로드/저장 ──────────────────────────────────
    const BM_PFX   = 'bm:';
    const MEMO_PFX = 'memo:';
    const CD_MAGIC = '_ContextData';

    const curPath = () => location.origin + location.pathname;
    const slug    = () => location.hostname.replace(/\./g, '_');

    const getBMKey   = () => BM_PFX   + curPath();
    const getMemoKey = () => MEMO_PFX + curPath();

    const loadBM  = ()  => gmGet(getBMKey(), []);
    const saveBM  = (d) => { try { gmSet(getBMKey(), d); _snapBM = JSON.stringify(d); } catch { toast('저장 실패'); } };
    const loadMemo  = ()     => gmGet(getMemoKey(), null);
    const saveMemo  = (text) => { gmSet(getMemoKey(), text); _snapMemo = text; };
    const delMemo   = ()     => gmDel(getMemoKey());
    const posOn     = ()  => gmGet('pos-enabled', false);
    const setPosOn  = (v) => gmSet('pos-enabled', v);
    const savePos   = (y) => gmSet('pos:' + curPath(), y);

    // ── 탭 간 스냅샷 ──────────────────────────────────────────
    let _snapMemo, _snapBM;

    // ── AES-256-GCM (ContextData 파일 수준 전용) ──────────────────
    const b64e = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
    const b64d = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

    const aesDerive = async (pw, salt) => {
        const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name:'PBKDF2', salt, iterations:200000, hash:'SHA-256' },
            km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
        );
    };

    // ── 메모 자체 암호화 (GM 스토리지 저장 수준) ──────────────
    const MEMO_MAGIC = '_memenc';
    let _memoKey = null; // 세션 중 메모리에만 보관

    const memoEncrypt = async (text, pw) => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv   = crypto.getRandomValues(new Uint8Array(12));
        const ct   = await crypto.subtle.encrypt(
            { name:'AES-GCM', iv }, await aesDerive(pw, salt), new TextEncoder().encode(text)
        );
        return JSON.stringify({ [MEMO_MAGIC]:true, salt:b64e(salt), iv:b64e(iv), data:b64e(ct) });
    };

    const memoDecrypt = async (stored, pw) => {
        try {
            const w = JSON.parse(stored);
            if (!w[MEMO_MAGIC]) return null;
            const pt = await crypto.subtle.decrypt(
                { name:'AES-GCM', iv:b64d(w.iv) }, await aesDerive(pw, b64d(w.salt)), b64d(w.data)
            );
            return new TextDecoder().decode(pt);
        } catch { return null; }
    };

    const isMemoEncrypted = (stored) => {
        if (!stored) return false;
        try { return !!JSON.parse(stored)[MEMO_MAGIC]; } catch { return false; }
    };

    // ── 공통 모달 팩토리 ───────────────────────────────────────
    const iCSS = { display:'block', width:'100%', padding:'7px 10px', marginBottom:'8px',
                   borderRadius:'6px', border:'1px solid rgba(255,255,255,.18)',
                   background:'rgba(255,255,255,.08)', color:'#fff',
                   fontSize:'13px', outline:'none', boxSizing:'border-box' };

    const mkModal = (w = 300, bg = '#1a1a1a') => {
        const ov = el('div');
        css(ov, { position:'fixed', inset:'0', background:'rgba(0,0,0,.65)', zIndex:'2147483647',
                  display:'flex', alignItems:'center', justifyContent:'center', fontFamily:'Arial,sans-serif' });
        const bx = el('div');
        css(bx, { background:bg, color:'#f0f0f0', borderRadius:'12px', padding:'20px 22px',
                  maxWidth:w+'px', width:'90%', boxShadow:'0 8px 32px rgba(0,0,0,.7)', lineHeight:'1.5' });
        ov.appendChild(bx); document.body.appendChild(ov);
        return { ov, append: (...ns) => ns.forEach(n => bx.appendChild(n)) };
    };

    const mkBtn = (text, bg, fn) => {
        const b = el('button', { textContent:text });
        css(b, { padding:'6px 12px', borderRadius:'6px', border:'none',
                 background:bg, color:'#fff', fontSize:'12px', cursor:'pointer' });
        b.onclick = fn; return b;
    };

    const mkBtnRow = (...btns) => {
        const r = el('div');
        css(r, { display:'flex', gap:'6px', justifyContent:'flex-end', flexWrap:'wrap' });
        btns.forEach(b => r.appendChild(b)); return r;
    };

    const mkTitle = (text, mb = '12px') => {
        const t = el('div', { textContent:text });
        css(t, { fontWeight:'bold', fontSize:'13px', marginBottom:mb }); return t;
    };

    // ── 메모 비밀번호 입력 모달 (단순 입력) ──────────────────
    // resolve(pw문자열) 또는 resolve(null, 취소)
    const promptMemoPw = (title, placeholder) => new Promise(resolve => {
        const { ov, append } = mkModal(280);
        const pw  = el('input', { type:'password', placeholder: placeholder || '비밀번호', maxLength:128 });
        css(pw, iCSS);
        const err = el('div'); css(err, { fontSize:'11px', color:'#f88', minHeight:'16px', marginBottom:'8px' });
        const close = () => { ov.remove(); resolve(null); };
        const doOk  = () => {
            const v = pw.value;
            if (!v || v.length < 4) { err.textContent = '4자 이상 입력하세요'; return; }
            ov.remove(); resolve(v);
        };
        pw.addEventListener('keydown', e => { if (e.key === 'Enter') doOk(); if (e.key === 'Escape') close(); });
        append(mkTitle(title), pw, err, mkBtnRow(mkBtn('확인','#2980b9',doOk), mkBtn('취소','#555',close)));
        pw.focus();
    });

    // 비밀번호 설정 모달: 새 비밀번호 두 번 입력
    // resolve(pw문자열) 또는 resolve(null, 취소)
    const promptNewMemoPw = () => new Promise(resolve => {
        const { ov, append } = mkModal(300);
        const pw1 = el('input', { type:'password', placeholder:'새 비밀번호 (4자 이상)', maxLength:128 });
        const pw2 = el('input', { type:'password', placeholder:'비밀번호 확인', maxLength:128 });
        const err = el('div'); css(err, { fontSize:'11px', color:'#f88', minHeight:'16px', marginBottom:'8px' });
        [pw1, pw2].forEach(i => css(i, { ...iCSS, marginBottom:'6px' }));
        pw2.style.display = 'none';
        pw1.addEventListener('input', () => { pw2.style.display = pw1.value ? '' : 'none'; err.textContent = ''; });
        const close = () => { ov.remove(); resolve(null); };
        const doSet = () => {
            const [v1, v2] = [pw1.value, pw2.value];
            if (!v1 || v1.length < 4) { err.textContent = '4자 이상 입력하세요'; return; }
            if (v1 !== v2) { err.textContent = '비밀번호가 일치하지 않습니다'; return; }
            ov.remove(); resolve(v1);
        };
        [pw1, pw2].forEach(i => i.addEventListener('keydown', e => {
            if (e.key === 'Enter') doSet(); if (e.key === 'Escape') close();
        }));
        const desc = el('div', { textContent:'메모가 GM 스토리지에 AES-256으로 암호화되어 저장됩니다.\n비밀번호 분실 시 복구 불가합니다.' });
        css(desc, { fontSize:'11px', color:'#aaa', marginBottom:'12px', whiteSpace:'pre-line' });
        append(mkTitle('🔑 메모 암호화 설정', '6px'), desc, pw1, pw2, err,
               mkBtnRow(mkBtn('설정','#27ae60',doSet), mkBtn('취소','#555',close)));
        pw1.focus();
    });

    // ── 내보내기 비밀번호 모달 ─────────────────────────────────
    const showExportPwModal = (onEncrypt, onPlain) => {
        const { ov, append } = mkModal(300);
        const pw1 = el('input', { type:'password', placeholder:'암호화 비밀번호 (선택, 4자 이상)', maxLength:128 });
        const pw2 = el('input', { type:'password', placeholder:'비밀번호 확인', maxLength:128 });
        const err = el('div'); css(err, { fontSize:'11px', color:'#f88', minHeight:'16px', marginBottom:'8px' });
        [pw1, pw2].forEach(i => css(i, { ...iCSS, marginBottom:'6px' }));
        pw2.style.display = 'none';
        pw1.addEventListener('input', () => { pw2.style.display = pw1.value ? '' : 'none'; err.textContent = ''; });
        const doSave = () => {
            const [v1, v2] = [pw1.value, pw2.value];
            if (v1 && v1.length < 4) { err.textContent = '4자 이상 입력하세요'; return; }
            if (v1 && v1 !== v2)     { err.textContent = '비밀번호가 일치하지 않습니다'; return; }
            ov.remove(); v1 ? onEncrypt(v1) : onPlain();
        };
        [pw1, pw2].forEach(i => i.addEventListener('keydown', e => {
            if (e.key === 'Enter') doSave(); if (e.key === 'Escape') ov.remove();
        }));
        const desc = el('div', { textContent:'비밀번호 입력 시 파일 전체를 AES-256 암호화합니다.\n비워두면 평문으로 저장됩니다.' });
        css(desc, { fontSize:'11px', color:'#aaa', marginBottom:'12px', whiteSpace:'pre-line' });
        append(mkTitle('📤 ContextData 내보내기', '6px'), desc, pw1, pw2, err,
               mkBtnRow(mkBtn('저장','#2980b9',doSave), mkBtn('취소','#555',()=>ov.remove())));
        pw1.focus();
    };

    // ── 복호화 비밀번호 모달 ──────────────────────────────────
    const showPwModal = (onConfirm, onCancel) => {
        const { ov, append } = mkModal(280);
        const pw  = el('input', { type:'password', placeholder:'복호화 비밀번호', maxLength:128 }); css(pw, iCSS);
        const err = el('div'); css(err, { fontSize:'11px', color:'#f88', minHeight:'16px', marginBottom:'8px' });
        const close = () => { ov.remove(); onCancel?.(); };
        const doOk  = () => { const v=pw.value; if (!v||v.length<4){err.textContent='4자 이상 입력하세요';return;} ov.remove(); onConfirm(v); };
        pw.addEventListener('keydown', e => { if (e.key==='Enter') doOk(); if (e.key==='Escape') close(); });
        append(mkTitle('🔒 비밀번호 입력'), pw, err,
               mkBtnRow(mkBtn('확인','#2980b9',doOk), mkBtn('취소','#555',close)));
        pw.focus();
    };

    // ── 불러오기 방식 선택 모달 ───────────────────────────────
    const makeImportDialog = (title, desc, info, onReplace, onMerge) => {
        const { ov, append } = mkModal(320, '#2a2a2a');
        const t = el('div',{textContent:title}); css(t,{fontWeight:'bold',fontSize:'14px',marginBottom:'8px'});
        const d = el('div',{textContent:desc});  css(d,{fontSize:'12px',color:'#f0a040',marginBottom:'16px'});
        const i = el('div',{innerHTML:info});    css(i,{fontSize:'11px',color:'#bbb',marginBottom:'18px',lineHeight:'1.6'});
        const go = fn => () => { ov.remove(); fn(); };
        append(t, d, i, mkBtnRow(
            mkBtn('덮어쓰기','#c0392b',go(onReplace)),
            mkBtn('병합','#2980b9',go(onMerge)),
            mkBtn('취소','#555',()=>ov.remove())
        ));
    };

    // ── ContextData 다운로드 ──────────────────────────────────────
    const _dlRaw = (blob, name) => {
        const a = el('a', { href:URL.createObjectURL(blob), download:name });
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    };

    const downloadContextData = (obj, base, onDone) => {
        const fname = base.replace(/\.json$/i,'') + '.ContextData';
        showExportPwModal(
            async (pw) => {
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv   = crypto.getRandomValues(new Uint8Array(12));
                const ct   = await crypto.subtle.encrypt(
                    { name:'AES-GCM', iv }, await aesDerive(pw, salt), new TextEncoder().encode(JSON.stringify(obj))
                );
                _dlRaw(new Blob([JSON.stringify({[CD_MAGIC]:true, salt:b64e(salt), iv:b64e(iv), data:b64e(ct)})],
                                {type:'application/octet-stream'}), fname);
                onDone?.('암호화');
            },
            () => { _dlRaw(new Blob([JSON.stringify(obj,null,2)],{type:'application/json'}),fname); onDone?.('평문'); }
        );
    };

    // ── 범용 export / clear ────────────────────────────────────
    const exportByScope = (pfx, scope) => {
        const isBM = pfx === BM_PFX, out = {};
        for (const k of gmKeys()) {
            if (!k.startsWith(scope)) continue;
            const d = gmGet(k, isBM ? [] : null);
            if (isBM ? d.length : d !== null) out[k.slice(pfx.length)] = d;
        }
        return out;
    };
    const exportCur = (pfx) => {
        const isBM = pfx === BM_PFX, d = gmGet(pfx+curPath(), isBM?[]:'');
        if (isBM ? !d.length : d === null) return null;
        return { [curPath()]: d };
    };
    const clearByScope = (scope) => { for (const k of gmKeys()) { if (k.startsWith(scope)) gmDel(k); } };

    const exportBMCurrent   = () => exportCur(BM_PFX);
    const exportBMDomain    = () => { const o=exportByScope(BM_PFX,BM_PFX+location.origin); return Object.keys(o).length?o:null; };
    const exportBMAll       = () => exportByScope(BM_PFX, BM_PFX);
    const exportMemoCurrent = () => exportCur(MEMO_PFX);
    const exportMemoDomain  = () => { const o=exportByScope(MEMO_PFX,MEMO_PFX+location.origin); return Object.keys(o).length?o:null; };
    const exportMemoAll     = () => exportByScope(MEMO_PFX, MEMO_PFX);

    const clearBMCurrent   = () => gmDel(getBMKey());
    const clearBMDomain    = () => clearByScope(BM_PFX   + location.origin);
    const clearBMAll       = () => clearByScope(BM_PFX);
    // 암호화 메모 삭제는 반드시 잠금 해제 후 호출해야 함
    // (호출 전에 ensureMemoUnlocked로 검증)
    const clearMemoCurrent = () => gmDel(getMemoKey());
    const clearMemoDomain  = () => { gmKeys().filter(k=>k.startsWith(MEMO_PFX+location.origin)).forEach(k=>gmDel(k)); };
    const clearMemoAll     = () => { gmKeys().filter(k=>k.startsWith(MEMO_PFX)).forEach(k=>gmDel(k)); _memoKey=null; };

    const confirmClear = (msg, fn, cb) => { if (!confirm(msg)) return; fn(); cb(); };

    // ── 불러오기 ──────────────────────────────────────────────
    const importBMJSON = (obj, mode) => {
        let added = 0, skipped = 0, replaced = 0;
        for (const [url, bms] of Object.entries(obj)) {
            if (!Array.isArray(bms)) continue;
            const key = BM_PFX + url;
            if (mode === 'replace') { gmSet(key, bms); replaced += bms.length; }
            else {
                const ex = gmGet(key, []);
                for (const bm of bms) {
                    if (ex.some(e => Math.abs(e.y-bm.y)<10)){skipped++;continue;}
                    ex.push(bm); added++;
                }
                gmSet(key, ex);
            }
        }
        return mode==='replace' ? `덮어쓰기 완료: ${replaced}개 적용` : `병합 완료: ${added}개 추가, ${skipped}개 중복 건너뜀`;
    };

    const showBMImportDialog = (obj, onDone) => {
        const hasConflict = Object.keys(obj).some(u => gmGet(BM_PFX+u,[]).length>0);
        if (!hasConflict) { onDone(importBMJSON(obj,'merge')); return; }
        const urls=Object.keys(obj).length, cnt=Object.values(obj).reduce((s,a)=>s+(Array.isArray(a)?a.length:0),0);
        makeImportDialog('불러오기 방식 선택', `${urls}개 URL, ${cnt}개 북마크 — 기존 데이터와 충돌 있음`,
            '<b>덮어쓰기</b>: 같은 URL의 기존 북마크를 파일 내용으로 완전 대체<br><b>병합</b>: 기존 유지 + 비중복 항목만 추가 (±10px 기준)',
            ()=>onDone(importBMJSON(obj,'replace')), ()=>onDone(importBMJSON(obj,'merge')));
    };

    const importMemoJSON = async (obj, mode) => {
        const entries = Object.entries(obj).filter(([, t]) => typeof t === 'string');
        let added = 0, skipped = 0, skipAll = false;

        for (let i = 0; i < entries.length; i++) {
            const [url, text] = entries[i];
            const key      = MEMO_PFX + url;
            const existing = gmGet(key, null);

            // 기존 메모 없으면 그냥 추가
            if (existing === null) { gmSet(key, text); added++; continue; }

            // 병합 모드에서 기존 평문 메모 → 건너뜀
            if (mode === 'merge' && !isMemoEncrypted(existing)) { skipped++; continue; }

            // 기존 메모가 있음(암호화 포함) → URL별 개별 확인
            if (skipAll) { skipped++; continue; }

            const isEnc = isMemoEncrypted(existing);
            const result = await new Promise(resolve => {
                const { ov, append } = mkModal(340, '#2a2a2a');
                const prog = el('div', { textContent: `불러오기 (${i + 1} / ${entries.length})` });
                css(prog, { fontSize: '11px', color: '#888', marginBottom: '4px' });
                const urlEl = el('div', { textContent: url });
                css(urlEl, { fontSize: '10px', color: '#aaa', marginBottom: '8px',
                             wordBreak: 'break-all', maxHeight: '40px', overflow: 'hidden' });
                const stateEl = el('div', { textContent: isEnc ? '⚠️ 기존 메모가 암호화 상태입니다' : '기존 메모가 있습니다' });
                css(stateEl, { fontSize: '11px', color: isEnc ? '#ffd700' : '#bbb', marginBottom: '12px' });

                let pwInput = null, errEl = null;
                if (isEnc) {
                    pwInput = el('input', { type: 'password', placeholder: '기존 메모 비밀번호 (삭제 승인)', maxLength: 128 });
                    css(pwInput, iCSS);
                    errEl = el('div'); css(errEl, { fontSize: '11px', color: '#f88', minHeight: '16px', marginBottom: '8px' });
                }

                const doConfirm = async () => {
                    if (isEnc) {
                        const v = pwInput.value;
                        if (!v || v.length < 4) { errEl.textContent = '4자 이상 입력하세요'; return; }
                        const res = await memoDecrypt(existing, v);
                        if (res === null) { errEl.textContent = '비밀번호가 맞지 않습니다'; pwInput.select(); return; }
                    }
                    ov.remove(); resolve('ok');
                };
                const doSkip    = () => { ov.remove(); resolve('skip'); };
                const doSkipAll = () => { ov.remove(); resolve('skipAll'); };
                const doCancel  = () => { ov.remove(); resolve('cancel'); };

                const nodes = [mkTitle('📥 기존 메모 덮어쓰기 확인', '6px'), prog, urlEl, stateEl];
                if (isEnc) nodes.push(pwInput, errEl);
                nodes.push(mkBtnRow(
                    mkBtn('덮어쓰기 확인', '#c0392b', doConfirm),
                    mkBtn('건너뛰기',      '#555',    doSkip),
                    mkBtn('모두 건너뛰기', '#444',    doSkipAll),
                    mkBtn('전체 취소',     '#333',    doCancel)
                ));
                append(...nodes);
                (pwInput || nodes[0]).focus?.();
                if (pwInput) pwInput.addEventListener('keydown', e => {
                    if (e.key === 'Enter') doConfirm(); if (e.key === 'Escape') doCancel();
                });
            });

            if (result === 'cancel')  return null;
            if (result === 'skipAll') { skipped++; skipAll = true; continue; }
            if (result === 'skip')    { skipped++; continue; }
            // 'ok'
            gmSet(key, text); added++;
        }

        if (added === 0 && skipped === 0) return null; // 전체 취소
        return `불러오기 완료: ${added}개 적용${skipped ? `, ${skipped}개 건너뜀` : ''}`;
    };

    const showMemoImportDialog = async (obj, onDone) => {
        const msg = await importMemoJSON(obj, 'merge');
        if (msg === null) return;
        onDone(msg);
    };

    // ── ContextData 파일 불러오기 ──────────────────────────────────
    const _decryptContextData = async (w, pw) => {
        try {
            const pt = await crypto.subtle.decrypt(
                {name:'AES-GCM',iv:b64d(w.iv)}, await aesDerive(pw,b64d(w.salt)), b64d(w.data)
            );
            return JSON.parse(new TextDecoder().decode(pt));
        } catch { return null; }
    };

    const triggerFileImport = (onParsed) => {
        const inp = el('input', { type:'file', accept:'.ContextData,.json' });
        css(inp, { position:'fixed', opacity:'0', pointerEvents:'none' });
        document.body.appendChild(inp);
        inp.onchange = () => {
            const file=inp.files[0]; inp.remove(); if(!file) return;
            const reader=new FileReader();
            reader.onload = async (e) => {
                let parsed; try{parsed=JSON.parse(e.target.result);}catch{toast('파일 형식 오류');return;}
                if (!parsed[CD_MAGIC]){onParsed(parsed);return;}
                showPwModal(async (pw) => {
                    const result=await _decryptContextData(parsed,pw);
                    if(result===null){toast('비밀번호가 맞지 않거나 손상된 파일입니다');return;}
                    onParsed(result);
                });
            };
            reader.readAsText(file);
        };
        inp.click();
    };

    // ── 패널 (Shadow DOM) ──────────────────────────────────────
    const host = el('div');
    css(host, { position:'fixed', right:'16px', bottom:'16px', zIndex:'2147483647', display:'none' });
    document.body.appendChild(host);
    const shadow = host.attachShadow({ mode:'open' });

    shadow.innerHTML = `<style>
        *{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,sans-serif}
        #p{width:260px;background:rgba(18,18,18,.45);color:#fff;border-radius:12px;
           border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(8px);overflow:hidden;
           display:flex;flex-direction:column;transition:background .2s;user-select:none}
        #p:hover{background:rgba(18,18,18,.92)}
        #dh{display:flex;align-items:center;justify-content:space-between;padding:8px 10px 6px;
            cursor:grab;border-bottom:1px solid rgba(255,255,255,.08);flex-shrink:0}
        #dh:active{cursor:grabbing}
        #dh span{font-size:11px;color:rgba(255,255,255,.5)}
        #tabs{display:flex;flex-shrink:0;border-bottom:1px solid rgba(255,255,255,.08)}
        .tab{flex:1;padding:5px 0;font-size:11px;text-align:center;cursor:pointer;
             color:rgba(255,255,255,.4);transition:color .15s,background .15s;user-select:none}
        .tab:hover{color:rgba(255,255,255,.7);background:rgba(255,255,255,.05)}
        .tab.on{color:#fff;border-bottom:2px solid rgba(255,255,255,.45)}
        #bm-sec,#mo-sec{display:flex;flex-direction:column}
        #l{overflow-y:auto;max-height:200px;padding:6px 8px}
        #l::-webkit-scrollbar{width:4px}
        #l::-webkit-scrollbar-thumb{background:rgba(255,255,255,.2);border-radius:2px}
        #ft{padding:6px 8px;border-top:1px solid rgba(255,255,255,.08);display:flex;gap:4px;flex-shrink:0}
        #mo-ta{resize:none;background:rgba(255,255,255,.06);color:#fff;border:none;outline:none;
               padding:8px;font-size:12px;line-height:1.5;min-height:150px;max-height:240px;width:100%;user-select:text}
        #mo-ta::placeholder{color:rgba(255,255,255,.25)}
        #mo-ta:focus{background:rgba(255,255,255,.1)}
        #mo-ft{padding:5px 8px;border-top:1px solid rgba(255,255,255,.08);display:flex;gap:3px;flex-shrink:0}
        .io-row{padding:4px 8px 2px;border-top:1px solid rgba(255,255,255,.08);display:flex;gap:3px;flex-shrink:0}
        .cl-row{padding:2px 8px 6px;display:flex;gap:3px;flex-shrink:0}
        .row{display:flex;align-items:center;gap:3px;margin-bottom:4px}
        button{background:rgba(255,255,255,.1);color:#fff;border:1px solid rgba(255,255,255,.15);
               border-radius:6px;font-size:11px;padding:3px 6px;cursor:pointer;white-space:nowrap;
               transition:background .15s;flex-shrink:0}
        button:hover{background:rgba(255,255,255,.22)}
        button:active{background:rgba(255,255,255,.3)}
        button:disabled{opacity:.35;cursor:default}
        .go{flex:1;text-align:left;overflow:hidden;text-overflow:ellipsis}
        .dl{color:#f88;border-color:rgba(255,100,100,.3)}
        .dl:hover{background:rgba(255,80,80,.25)}
        .io-btn{flex:1;font-size:10px;padding:3px 2px;text-align:center}
        .cl-btn{flex:1;font-size:10px;padding:3px 2px;text-align:center;
                color:#f99;border-color:rgba(255,120,120,.25)}
        .cl-btn:hover{background:rgba(255,80,80,.25)}
        .io-sep{font-size:10px;color:rgba(255,255,255,.3);display:flex;align-items:center;padding:0 1px}
        .sm-btn{font-size:10px;padding:2px 5px}
        input{flex:1;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);
              border-radius:6px;color:#fff;font-size:11px;padding:3px 7px;outline:none}
        input::placeholder{color:rgba(255,255,255,.35)}
        input:focus{border-color:rgba(255,255,255,.45);background:rgba(255,255,255,.15)}
        #tk{position:absolute;bottom:calc(100% + 8px);right:0;background:rgba(50,50,50,.95);
            color:#fff;font-size:11px;padding:5px 10px;border-radius:7px;
            pointer-events:none;opacity:0;transition:opacity .2s;max-width:260px;white-space:normal;text-align:right}
        #tk.on{opacity:1}
        .hint{font-size:11px;color:rgba(255,255,255,.3);text-align:center;padding:10px 0}
    </style>
    <div id="p">
      <div id="dh"><span>&#9776; 다기능 메뉴</span><button id="cb">&#x2715;</button></div>
      <div id="tabs"><div class="tab on" id="tb-bm">🔖 스크롤 북마크</div><div class="tab" id="tb-mo">📝 메모</div></div>
      <div id="bm-sec">
        <div id="l"></div>
        <div id="ft"><input id="ni" placeholder="이름 입력 후 추가..." maxlength="30"><button id="ab">+ 추가</button></div>
        <div class="io-row">
          <button class="io-btn" id="bx-cur">📤 현재</button>
          <button class="io-btn" id="bx-dom">📤 도메인</button>
          <button class="io-btn" id="bx-all">📤 전체</button>
          <span class="io-sep">|</span>
          <button class="io-btn" id="bi-btn">📥 불러오기</button>
        </div>
        <div class="cl-row">
          <button class="cl-btn" id="bc-cur">🗑 현재</button>
          <button class="cl-btn" id="bc-dom">🗑 도메인</button>
          <button class="cl-btn" id="bc-all">🗑 전체</button>
        </div>
      </div>
      <div id="mo-sec" style="display:none">
        <textarea id="mo-ta" placeholder="메모 공간입니다.&#10;&#10;암호화가 필요하면 🔓 잠금 버튼을 누르세요."></textarea>
        <div id="mo-ft">
          <button id="mo-save" style="flex:1">💾 저장</button>
          <button id="mo-lock" class="sm-btn">🔓 잠금</button>
          <button id="mo-del" class="dl sm-btn">🗑 삭제</button>
        </div>
        <div class="io-row">
          <button class="io-btn" id="mx-cur">📤 현재</button>
          <button class="io-btn" id="mx-dom">📤 도메인</button>
          <button class="io-btn" id="mx-all">📤 전체</button>
          <span class="io-sep">|</span>
          <button class="io-btn" id="mi-btn">📥 불러오기</button>
        </div>
        <div class="cl-row">
          <button class="cl-btn" id="mc-cur">🗑 현재</button>
          <button class="cl-btn" id="mc-dom">🗑 도메인</button>
          <button class="cl-btn" id="mc-all">🗑 전체</button>
        </div>
      </div>
      <div id="tk"></div>
    </div>`;

    // ── 패널 요소 참조 ─────────────────────────────────────────
    const $  = id => shadow.getElementById(id);
    const [dh,list,ni,ab,tk,cb,tabBm,tabMo,bmSec,moSec,moTa,moSave,moLock,moDel]
        = ['dh','l','ni','ab','tk','cb','tb-bm','tb-mo','bm-sec','mo-sec','mo-ta','mo-save','mo-lock','mo-del'].map($);

    // ── 토스트 ─────────────────────────────────────────────────
    let tkT;
    const toast = msg => { tk.textContent=msg; tk.classList.add('on'); clearTimeout(tkT); tkT=setTimeout(()=>tk.classList.remove('on'),2800); };

    // ── 패널 ──────────────────────────────────────────────────
    const showPanel = () => { host.style.display=''; activeTab==='bm'?renderBM():renderMemo(); };
    const hidePanel = () => { host.style.display='none'; };
    const panelOn   = () => host.style.display !== 'none';

    // ── 탭 전환 ────────────────────────────────────────────────
    let activeTab = 'bm';
    const switchTab = tab => {
        activeTab=tab;
        tabBm.classList.toggle('on',tab==='bm'); tabMo.classList.toggle('on',tab==='mo');
        bmSec.style.display=tab==='bm'?'flex':'none'; moSec.style.display=tab==='mo'?'flex':'none';
        tab==='bm'?renderBM():renderMemo();
    };
    tabBm.onclick=()=>switchTab('bm'); tabMo.onclick=()=>switchTab('mo');

    // ── 북마크 렌더 ────────────────────────────────────────────
    function renderBM() {
        list.innerHTML='';
        const bms=loadBM();
        if (!bms.length){list.innerHTML='<div class="hint">북마크가 없습니다</div>';return;}
        bms.forEach((bm,i)=>{
            const row=el('div',{className:'row'});
            const mkB=(t,cls,fn)=>{const b=el('button',{textContent:t,className:cls||''});b.onclick=fn;return b;};
            const go=mkB(bm.name||`#${i+1} (${Math.round(bm.y)}px)`,'go',()=>scrollTo({top:bm.y,behavior:'instant'}));
            go.title=Math.round(bm.y)+'px';

            const edit=mkB('\u270E','',()=>{
                row.innerHTML=''; let newY=bm.y;
                const wrap=el('div'); wrap.style.cssText='display:flex;flex-direction:column;gap:3px;flex:1;min-width:0';
                const rA=el('div'); rA.style.cssText='display:flex;gap:3px';
                const inp=el('input',{value:bm.name||'',maxLength:30,placeholder:'이름'});
                rA.appendChild(inp);
                const rB=el('div'); rB.style.cssText='display:flex;gap:3px;align-items:center';
                const lbl=el('span'); lbl.style.cssText='flex:1;font-size:10px;color:rgba(255,255,255,.45);overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
                lbl.textContent=`📍 ${Math.round(newY)}px`;
                const posBtn=mkB('현재 위치로','',()=>{newY=scrollY;lbl.textContent=`📍 ${Math.round(newY)}px`;lbl.style.color='#7ddf7d';});
                posBtn.style.fontSize='10px'; rB.append(lbl,posBtn);
                const rC=el('div'); rC.style.cssText='display:flex;gap:3px';
                const save=mkB('저장','',()=>{const a=loadBM();a[i].name=inp.value.trim();a[i].y=newY;saveBM(a);renderBM();});
                rC.append(save,mkB('취소','',renderBM));
                inp.onkeydown=e=>{if(e.key==='Enter')save.onclick();if(e.key==='Escape')renderBM();};
                wrap.append(rA,rB,rC); row.appendChild(wrap);
                inp.focus(); inp.select();
            });

            const swap=(a,j)=>{const t=a[i];a[i]=a[j];a[j]=t;};
            const up=mkB('\u2191','',()=>{if(!i)return;const a=loadBM();swap(a,i-1);saveBM(a);renderBM();});
            const dn=mkB('\u2193','',()=>{const a=loadBM();if(i===a.length-1)return;swap(a,i+1);saveBM(a);renderBM();});
            const del=mkB('\u2715','dl',()=>{const a=loadBM();a.splice(i,1);saveBM(a);renderBM();});
            up.disabled=i===0;
            row.append(go,edit,up,dn,del); list.appendChild(row);
        });
    }

    const addBM=()=>{const name=ni.value.trim(),arr=loadBM();arr.push({y:scrollY,name,time:Date.now()});saveBM(arr);ni.value='';renderBM();toast(`"${name||'#'+arr.length}" 저장됨 (${Math.round(scrollY)}px)`);};
    ab.onclick=addBM; ni.onkeydown=e=>{if(e.key==='Enter')addBM();};

    // ── 메모 ──────────────────────────────────────────────────
    // _memoKey: null = 평문모드, 문자열 = 암호화모드(세션 메모리)
    // 규칙:
    //   - _memoKey 있으면 저장 시 항상 암호화, 없으면 항상 평문
    //   - 암호화된 메모에 접근하려면 반드시 ensureUnlocked() 먼저

    // 표시용: 암호화 메모인데 _memoKey 없을 때 비밀번호 입력받아 _memoKey 세팅
    // 성공 true / 취소·실패 false — 저장소는 건드리지 않음
    const ensureUnlocked = async () => {
        const stored = loadMemo();
        if (!isMemoEncrypted(stored)) return true;
        if (_memoKey) return true;
        const pw = await promptMemoPw('🔒 메모 잠금 해제', '비밀번호');
        if (!pw) return false;
        const plain = await memoDecrypt(stored, pw);
        if (plain === null) { toast('비밀번호가 맞지 않습니다'); return false; }
        _memoKey = pw;
        moTa.readOnly = false;
        return true;
    };

    // 파괴적 작업용: 암호화 메모 각각 개별 비밀번호 확인
    // 반환: 삭제 승인된 키 배열 | null (전체 취소)
    // 건너뛴 키는 결과 배열에서 제외 → 호출자가 결과 배열의 키만 삭제
    const verifyEncryptedMemos = async (keys) => {
        const encKeys  = keys.filter(k => isMemoEncrypted(gmGet(k, null)));
        if (!encKeys.length) return keys;

        const plainKeys = keys.filter(k => !isMemoEncrypted(gmGet(k, null)));
        const approved  = [...plainKeys];
        let   skipAll   = false;

        for (let i = 0; i < encKeys.length; i++) {
            const k = encKeys[i];
            if (skipAll) continue;

            const url = k.startsWith(MEMO_PFX) ? k.slice(MEMO_PFX.length) : k;
            const result = await new Promise(resolve => {
                const { ov, append } = mkModal(340, '#2a2a2a');
                const prog = el('div', { textContent:`암호화 메모 (${i+1} / ${encKeys.length})` });
                css(prog, { fontSize:'11px', color:'#888', marginBottom:'4px' });
                const urlEl = el('div', { textContent: url });
                css(urlEl, { fontSize:'10px', color:'#aaa', marginBottom:'12px',
                             wordBreak:'break-all', maxHeight:'40px', overflow:'hidden' });
                const pw  = el('input', { type:'password', placeholder:'이 메모의 비밀번호', maxLength:128 });
                css(pw, iCSS);
                const err = el('div'); css(err, { fontSize:'11px', color:'#f88', minHeight:'16px', marginBottom:'8px' });

                const doConfirm = async () => {
                    const v = pw.value;
                    if (!v || v.length < 4) { err.textContent = '4자 이상 입력하세요'; return; }
                    const res = await memoDecrypt(gmGet(k, null), v);
                    if (res === null) { err.textContent = '비밀번호가 맞지 않습니다'; pw.select(); return; }
                    ov.remove(); resolve('ok');
                };
                const doSkip    = () => { ov.remove(); resolve('skip'); };
                const doSkipAll = () => { ov.remove(); resolve('skipAll'); };
                const doCancel  = () => { ov.remove(); resolve('cancel'); };

                pw.addEventListener('keydown', e => {
                    if (e.key === 'Enter') doConfirm(); if (e.key === 'Escape') doCancel();
                });
                append(
                    mkTitle('🔒 암호화 메모 삭제 확인', '6px'), prog, urlEl, pw, err,
                    mkBtnRow(
                        mkBtn('삭제 확인',     '#c0392b', doConfirm),
                        mkBtn('건너뛰기',      '#555',    doSkip),
                        mkBtn('모두 건너뛰기', '#444',    doSkipAll),
                        mkBtn('전체 취소',     '#333',    doCancel)
                    )
                );
                pw.focus();
            });

            if (result === 'cancel')  return null;
            if (result === 'ok')      approved.push(k);
            if (result === 'skipAll') skipAll = true;
        }
        return approved;
    };

    const updateMemoLockBtn = () => {
        const locked = isMemoEncrypted(loadMemo());
        const open   = locked && !!_memoKey;
        moLock.textContent = locked ? (open ? '🔓 잠김(열림)' : '🔒 잠김') : '🔓 잠금';
        moLock.title       = locked ? '암호화 설정 변경 / 해제' : '메모 암호화 설정';
        moLock.style.color = locked ? (open ? '#7ddf7d' : '#ffd700') : '';
    };

    const renderMemo = async () => {
        const stored = loadMemo();
        // 저장된 메모가 암호화 상태가 아닌데 _memoKey가 남아있으면 초기화
        if (_memoKey && !isMemoEncrypted(stored)) _memoKey = null;

        if (!stored) {
            moTa.value = ''; moTa.readOnly = false;
            moTa.placeholder = '메모 공간입니다.\n\n암호화가 필요하면 🔓 잠금 버튼을 누르세요.';
            updateMemoLockBtn(); return;
        }
        if (!isMemoEncrypted(stored)) {
            moTa.value = stored; moTa.readOnly = false;
            moTa.placeholder = '메모 공간입니다.';
            updateMemoLockBtn(); return;
        }
        // 암호화 메모: _memoKey 있으면 복호화해서 표시, 없으면 잠김(읽기전용)
        if (_memoKey) {
            const plain = await memoDecrypt(stored, _memoKey);
            if (plain !== null) {
                moTa.value = plain; moTa.readOnly = false;
                moTa.placeholder = '';
                updateMemoLockBtn(); return;
            }
            _memoKey = null; // 키 불일치
        }
        moTa.value = ''; moTa.readOnly = true;
        moTa.placeholder = '🔒 암호화된 메모입니다.';
        updateMemoLockBtn();
    };

    moSave.onclick = async () => {
        const stored = loadMemo();
        // 저장된 메모가 암호화 상태가 아닌데 _memoKey가 남아있으면 초기화
        if (_memoKey && !isMemoEncrypted(stored)) _memoKey = null;

        // 잠긴 상태 → 저장 불가
        if (isMemoEncrypted(stored) && !_memoKey) {
            toast('🔒 잠긴 상태입니다. 잠금 버튼으로 해제 후 수정하세요');
            return;
        }
        // 암호화 상태로 저장 → 비밀번호 재확인
        if (_memoKey) {
            const pw = await promptMemoPw('🔒 저장 확인', '저장할 비밀번호 입력');
            if (!pw) return;
            if (pw !== _memoKey) { toast('비밀번호가 맞지 않습니다'); return; }
            saveMemo(await memoEncrypt(moTa.value, _memoKey));
            toast('메모 저장됨 (암호화)');
        } else {
            saveMemo(moTa.value);
            toast('메모 저장됨');
        }
        updateMemoLockBtn();
    };

    moDel.onclick = async () => {
        const approved = await verifyEncryptedMemos([getMemoKey()]);
        if (approved === null || !approved.includes(getMemoKey())) return;
        if (!confirm('이 페이지의 메모를 삭제하시겠습니까?')) return;
        _memoKey = null;
        clearMemoCurrent();
        await renderMemo();
        toast('메모 삭제됨');
    };

    moLock.onclick = async () => {
        const stored = loadMemo();
        const locked = isMemoEncrypted(stored);

        if (!locked) {
            // ── 평문 → 암호화 설정 ──────────────────────────
            const pw = await promptNewMemoPw();
            if (!pw) return;
            _memoKey = pw;
            saveMemo(await memoEncrypt(moTa.value, pw));
            await renderMemo();
            toast('메모 암호화 설정 완료 — 저장 시 항상 암호화됩니다');
        } else if (!_memoKey) {
            // ── 잠긴 상태, 세션 키 없음 → 비밀번호 입력 후 표시만 ──
            if (!(await ensureUnlocked())) return;
            await renderMemo(); // 복호화해서 화면에 표시, GM 스토리지는 그대로 암호화
            toast('🔓 표시 중 — 저장 시 암호화 유지됩니다');
        } else {
            // ── 이미 열려 있음 → 옵션 모달 (비번변경 / 암호화해제) ──
            const plain = await memoDecrypt(stored, _memoKey);
            if (plain === null) { _memoKey = null; toast('키 불일치, 다시 잠금을 눌러 해제하세요'); updateMemoLockBtn(); return; }

            const { ov, append } = mkModal(300, '#2a2a2a');
            const info = el('div', { textContent:'현재 메모는 암호화 중입니다 (세션에서 열려 있음)' });
            css(info, { fontSize:'12px', color:'#bbb', marginBottom:'16px' });
            const doChangePw = async () => {
                ov.remove();
                const oldPw = await promptMemoPw('🔑 기존 비밀번호 확인', '현재 비밀번호');
                if (!oldPw) return;
                const check = await memoDecrypt(loadMemo(), oldPw);
                if (check === null) { toast('기존 비밀번호가 맞지 않습니다'); return; }
                const newPw = await promptNewMemoPw();
                if (!newPw) return;
                _memoKey = newPw;
                saveMemo(await memoEncrypt(plain, newPw));
                updateMemoLockBtn();
                toast('비밀번호 변경 완료');
            };
            const doRemoveEnc = async () => {
                ov.remove();
                const confirmPw = await promptMemoPw('🔓 암호화 해제 확인', '비밀번호를 다시 입력하세요');
                if (!confirmPw) return;
                const verified = await memoDecrypt(loadMemo(), confirmPw);
                if (verified === null) { toast('비밀번호가 맞지 않습니다'); return; }
                // 즉시 저장하지 않음 — textarea에만 평문 표시, 저장 버튼으로 확정
                _memoKey = null;
                moTa.value = verified;
                moTa.readOnly = false;
                moTa.placeholder = '메모 공간입니다.';
                updateMemoLockBtn();
                toast('✏️ 암호화 해제됨 — 확인 후 저장 버튼을 눌러 평문으로 저장하세요');
            };
            const doLockAgain = () => {
                ov.remove();
                _memoKey = null;
                moTa.value = ''; moTa.readOnly = true;
                moTa.placeholder = '🔒 암호화된 메모입니다.';
                updateMemoLockBtn();
                toast('다시 잠겼습니다');
            };
            append(
                mkTitle('🔑 암호화 설정', '10px'), info,
                mkBtnRow(
                    mkBtn('다시 잠그기',  '#555',    doLockAgain),
                    mkBtn('비밀번호 변경','#2980b9', doChangePw),
                    mkBtn('암호화 해제',  '#c0392b', doRemoveEnc)
                )
            );
        }
    };

    // ── 패널 IO 버튼 ──────────────────────────────────────────
    const bmBase=()=>`bookmarks_${slug()}`;
    const bmSum =o=>Object.values(o).reduce((s,a)=>s+a.length,0);
    const moBase=()=>`memo_${slug()}`;

    $('bx-cur').onclick=()=>{const o=exportBMCurrent();if(!o){toast('현재 페이지에 북마크가 없습니다');return;}downloadContextData(o,bmBase(),t=>toast(`현재 페이지 내보내기 완료 (${t})`));};
    $('bx-dom').onclick=()=>{const o=exportBMDomain(); if(!o){toast('현재 도메인에 북마크가 없습니다');return;} downloadContextData(o,bmBase()+'_all',t=>toast(`도메인 ${Object.keys(o).length}개 URL, ${bmSum(o)}개 완료 (${t})`));};
    $('bx-all').onclick=()=>{const o=exportBMAll();if(!Object.keys(o).length){toast('저장된 북마크가 없습니다');return;}downloadContextData(o,'bookmarks_all',t=>toast(`전체 ${Object.keys(o).length}개 URL, ${bmSum(o)}개 완료 (${t})`));};
    $('bi-btn').onclick=()=>triggerFileImport(o=>showBMImportDialog(o,msg=>{renderBM();toast(msg);}));
    $('bc-cur').onclick=()=>confirmClear('현재 페이지 북마크를 모두 삭제하시겠습니까?',  clearBMCurrent,()=>{renderBM();toast('현재 페이지 북마크 삭제 완료');});
    $('bc-dom').onclick=()=>confirmClear(`"${location.hostname}" 도메인의 모든 북마크를 삭제하시겠습니까?`,clearBMDomain, ()=>{renderBM();toast('도메인 북마크 전체 삭제 완료');});
    $('bc-all').onclick=()=>confirmClear('모든 페이지의 북마크를 전부 삭제하시겠습니까?',clearBMAll,    ()=>{renderBM();toast('전체 북마크 삭제 완료');});

    $('mx-cur').onclick=()=>{const o=exportMemoCurrent();if(!o){toast('현재 페이지에 메모가 없습니다');return;}downloadContextData(o,moBase(),t=>toast(`현재 페이지 메모 내보내기 완료 (${t})`));};
    $('mx-dom').onclick=()=>{const o=exportMemoDomain(); if(!o){toast('현재 도메인에 메모가 없습니다');return;} downloadContextData(o,moBase()+'_all',t=>toast(`도메인 ${Object.keys(o).length}개 URL 완료 (${t})`));};
    $('mx-all').onclick=()=>{const o=exportMemoAll();if(!Object.keys(o).length){toast('저장된 메모가 없습니다');return;}downloadContextData(o,'memo_all',t=>toast(`전체 ${Object.keys(o).length}개 URL 완료 (${t})`));};
    $('mi-btn').onclick=()=>triggerFileImport(async o=>{await showMemoImportDialog(o,msg=>{renderMemo();toast(msg);});});

    // 메모 초기화 — 암호화 메모 포함 범위면 URL별 개별 비밀번호 재검증
    $('mc-cur').onclick = async () => {
        const keys     = [getMemoKey()];
        const approved = await verifyEncryptedMemos(keys);
        if (approved === null) return;
        if (!approved.includes(getMemoKey())) { toast('건너뛰어 삭제 취소됨'); return; }
        if (!confirm('현재 페이지 메모를 삭제하시겠습니까?')) return;
        _memoKey = null; gmDel(getMemoKey()); await renderMemo(); toast('현재 페이지 메모 삭제 완료');
    };
    $('mc-dom').onclick = async () => {
        const keys     = gmKeys().filter(k => k.startsWith(MEMO_PFX + location.origin));
        if (!keys.length) { toast('현재 도메인에 메모가 없습니다'); return; }
        const approved = await verifyEncryptedMemos(keys);
        if (approved === null) return;
        if (!approved.length) { toast('삭제할 메모가 없습니다 (모두 건너뜀)'); return; }
        const skipped = keys.length - approved.length;
        if (!confirm(`"${location.hostname}" 도메인 메모 ${approved.length}개를 삭제하시겠습니까?${skipped ? ` (암호화 ${skipped}개 건너뜀)` : ''}`)) return;
        approved.forEach(k => gmDel(k));
        if (approved.includes(getMemoKey())) _memoKey = null;
        await renderMemo(); toast(`도메인 메모 ${approved.length}개 삭제 완료`);
    };
    $('mc-all').onclick = async () => {
        const keys     = gmKeys().filter(k => k.startsWith(MEMO_PFX));
        if (!keys.length) { toast('저장된 메모가 없습니다'); return; }
        const approved = await verifyEncryptedMemos(keys);
        if (approved === null) return;
        if (!approved.length) { toast('삭제할 메모가 없습니다 (모두 건너뜀)'); return; }
        const skipped = keys.length - approved.length;
        if (!confirm(`전체 메모 ${approved.length}개를 삭제하시겠습니까?${skipped ? ` (암호화 ${skipped}개 건너뜀)` : ''}`)) return;
        approved.forEach(k => gmDel(k));
        if (approved.includes(getMemoKey())) _memoKey = null;
        await renderMemo(); toast(`전체 메모 ${approved.length}개 삭제 완료`);
    };

    cb.onclick=hidePanel;

    // ── 드래그 ─────────────────────────────────────────────────
    let drag=false, ox=0, oy=0;
    dh.onmousedown=e=>{if(e.target===cb)return;drag=true;const r=host.getBoundingClientRect();ox=e.clientX-r.left;oy=e.clientY-r.top;e.preventDefault();};
    document.addEventListener('mousemove',e=>{if(!drag)return;host.style.left=Math.max(0,Math.min(e.clientX-ox,innerWidth-host.offsetWidth))+'px';host.style.top=Math.max(0,Math.min(e.clientY-oy,innerHeight-host.offsetHeight))+'px';host.style.right='auto';host.style.bottom='auto';});
    document.addEventListener('mouseup',()=>{drag=false;});

    // ── SPA URL 변경 감지 ──────────────────────────────────────
    ['pushState','replaceState'].forEach(m=>{const o=history[m];history[m]=function(...a){const r=o.apply(this,a);window.dispatchEvent(new Event('locationchange'));return r;};});
    window.addEventListener('popstate',()=>window.dispatchEvent(new Event('locationchange')));
    window.addEventListener('locationchange',()=>{_memoKey=null;if(!panelOn())return;activeTab==='bm'?renderBM():renderMemo().catch(()=>{});});

    // ── 탭 간 변경 감지 (폴링) ─────────────────────────────────
    _snapMemo=loadMemo(); _snapBM=JSON.stringify(loadBM());
    setInterval(()=>{
        const cm=loadMemo(),cb=JSON.stringify(loadBM());
        if(cm!==_snapMemo){_snapMemo=cm;if(panelOn()&&activeTab==='mo')renderMemo().catch(()=>{});}
        if(cb!==_snapBM)  {_snapBM=cb;  if(panelOn()&&activeTab==='bm')renderBM();}
    },1000);

    // ── 위치 기억 ──────────────────────────────────────────────
    (()=>{
        const target=gmGet('pos:'+curPath(),0);
        if(!posOn()||target<1)return;
        let done=false;
        const iv=setInterval(()=>{if(done)return;if(Math.abs(scrollY-target)<5){done=true;clearInterval(iv);}else scrollTo({top:target,behavior:'instant'});},150);
        setTimeout(()=>clearInterval(iv),10000);
    })();

    let posT;
    window.addEventListener('scroll',()=>{if(!posOn())return;clearTimeout(posT);posT=setTimeout(()=>savePos(scrollY),400);},{passive:true});

    // ── 컨텍스트 메뉴 ──────────────────────────────────────────
    document.head.appendChild(el('style',{textContent:`
        #cm{position:absolute;display:none;background:#fff;color:#111;border:1px solid #ddd;
            box-shadow:0 4px 16px rgba(0,0,0,.13);z-index:2147483646;padding:4px 0;
            font-family:Arial,sans-serif;font-size:13px;min-width:170px;border-radius:8px}
        #cm .mi{position:relative;padding:8px 14px;cursor:pointer;display:flex;
                align-items:center;justify-content:space-between;gap:8px}
        #cm .mi:hover{background:#f0f0f0}
        #cm .mi.sub::after{content:'\\25B6';font-size:9px;color:#aaa}
        #cm .mi.danger{color:#c00}
        #cm .mi.danger:hover{background:#fff0f0}
        #cm hr{border:none;border-top:1px solid #eee;margin:3px 0}
        #cm .lbl{padding:5px 14px 3px;font-size:11px;color:#aaa;cursor:default}
        #cm .bj{padding-left:24px;color:#555}
        #cm .bm-sc{max-height:200px;overflow-y:auto}
        #cm .bm-sc::-webkit-scrollbar{width:4px}
        #cm .bm-sc::-webkit-scrollbar-thumb{background:#ccc;border-radius:2px}
        .sw{position:absolute;left:100%;top:0;display:none;background:#fff;border:1px solid #ddd;
            box-shadow:0 4px 16px rgba(0,0,0,.13);border-radius:8px;min-width:170px;padding:4px 0;z-index:2147483647}
        .mi:hover>.sw{display:block}
        .sw .si{padding:7px 14px;cursor:pointer;font-size:12px;color:#222}
        .sw .si:hover{background:#f0f0f0}
        .sw .si.danger{color:#c00}
        .sw .si.danger:hover{background:#fff0f0}
    `}));

    const cm=el('div',{id:'cm'}); document.body.appendChild(cm);

    const mItem=(text,sub,danger)=>{
        const d=el('div',{className:'mi'+(sub?' sub':'')+(danger?' danger':''),textContent:text});
        if(sub){const sw=el('div',{className:'sw'});d.appendChild(sw);d._sw=sw;}
        return d;
    };
    const sItem=(text,fn,danger)=>{
        const d=el('div',{className:'si'+(danger?' danger':''),textContent:text});
        d.onclick=()=>{fn();hideCM();}; return d;
    };

    function buildCM() {
        cm.innerHTML='';
        const dec=decodeURIComponent(location.href);

        // URL 복사
        const urlItem=mItem('URL 복사',true);
        [['일반 (제목 + URL)',`${document.title}\n${dec}`],['마크다운',`[${document.title}](${dec})`],['링크 태그',`<a href="${dec}">${document.title}</a>`]]
            .forEach(([l,t])=>urlItem._sw.appendChild(sItem(l,()=>{clip(t);confirm2('URL 복사 완료');})));
        // 보안 URL 복사 (Argon2id / PBKDF2 선택 + AES-256-GCM) — 포맷 3종
        const secSep = el('div'); css(secSep, { borderTop:'1px solid #eee', margin:'3px 0' });
        urlItem._sw.appendChild(secSep);
        [
            ['🔐 보안 · 일반 (제목 + URL)', 'plain'],
            ['🔐 보안 · 마크다운',           'markdown'],
            ['🔐 보안 · 링크 태그',           'tag'],
        ].forEach(([label, fmt]) => {
            const si = sItem(label, () => { hideCM(); showSecureUrlCopyModal(fmt); });
            css(si, { color:'#1a9e6a', fontWeight:'bold' });
            urlItem._sw.appendChild(si);
        });
        cm.appendChild(urlItem);

        // DOM 복사
        const domItem=mItem('DOM 복사');
        domItem.onclick=()=>{clip(document.documentElement.outerHTML);confirm2('DOM 소스코드 복사 완료');hideCM();};
        cm.appendChild(domItem);

        // 위치 기억 토글
        const posItem=mItem(posOn()?'🔴 위치 기억 끄기':'🟢 위치 기억 켜기');
        posItem.onclick=()=>{setPosOn(!posOn());hideCM();}; cm.appendChild(posItem);

        // 메모 단축
        cm.appendChild(el('hr')); cm.appendChild(el('div',{className:'lbl',textContent:'PAGE MEMO'}));
        const moItem=mItem(loadMemo()!==null?'📝 메모 열기':'📝 메모 쓰기');
        moItem.onclick=()=>{hideCM();if(!panelOn())showPanel();switchTab('mo');}; cm.appendChild(moItem);

        // 북마크 섹션
        cm.appendChild(el('hr')); cm.appendChild(el('div',{className:'lbl',textContent:'SCROLL BOOKMARK'}));
        const tog=mItem(panelOn()?'📌 패널 닫기':'📌 패널 열기');
        tog.onclick=()=>{panelOn()?hidePanel():showPanel();hideCM();}; cm.appendChild(tog);

        // 북마크 내보내기
        const exp=mItem('📤 북마크 내보내기',true);
        [['현재 페이지만',()=>{const o=exportBMCurrent();if(!o){confirm2('현재 페이지에 북마크가 없습니다');return;}downloadContextData(o,bmBase(),t=>confirm2(`현재 페이지 내보내기 완료 (${t})`));}],
         ['현재 도메인 전체',()=>{const o=exportBMDomain();if(!o){confirm2('현재 도메인에 북마크가 없습니다');return;}downloadContextData(o,bmBase()+'_all',t=>confirm2(`도메인 ${Object.keys(o).length}개 URL, ${bmSum(o)}개 완료 (${t})`));}],
         ['모든 페이지',()=>{const o=exportBMAll();if(!Object.keys(o).length){confirm2('저장된 북마크가 없습니다');return;}downloadContextData(o,'bookmarks_all',t=>confirm2(`전체 ${Object.keys(o).length}개 URL, ${bmSum(o)}개 완료 (${t})`));}],
        ].forEach(([t,fn])=>exp._sw.appendChild(sItem(t,fn)));
        cm.appendChild(exp);

        // 북마크 불러오기
        const imp=mItem('📥 북마크 불러오기');
        imp.onclick=()=>{hideCM();triggerFileImport(o=>showBMImportDialog(o,msg=>{renderBM();confirm2(msg);}));}; cm.appendChild(imp);

        // 북마크 초기화
        const clr=mItem('🗑 북마크 초기화',true);
        [['현재 페이지만',()=>confirmClear('현재 페이지 북마크를 모두 삭제하시겠습니까?',  clearBMCurrent,()=>{renderBM();confirm2('현재 페이지 북마크 삭제 완료');})],
         ['현재 도메인 전체',()=>confirmClear(`"${location.hostname}" 도메인의 모든 북마크를 삭제하시겠습니까?`,clearBMDomain, ()=>{renderBM();confirm2('도메인 북마크 전체 삭제 완료');})],
         ['모든 페이지',()=>confirmClear('모든 페이지의 북마크를 전부 삭제하시겠습니까?',clearBMAll,    ()=>{renderBM();confirm2('전체 북마크 삭제 완료');})],
        ].forEach(([t,fn])=>clr._sw.appendChild(sItem(t,fn,true)));
        cm.appendChild(clr);

        // 북마크 목록
        const bms=loadBM();
        if(bms.length){
            cm.appendChild(el('hr'));
            const wrap=el('div',{className:'bm-sc'});
            bms.forEach((bm,i)=>{
                const b=mItem(bm.name||`#${i+1} (${Math.round(bm.y)}px)`);
                b.classList.add('bj'); b.title=Math.round(bm.y)+'px';
                b.onclick=()=>{scrollTo({top:bm.y,behavior:'instant'});hideCM();};
                wrap.appendChild(b);
            });
            cm.appendChild(wrap);
        }
    }

    const showCM=e=>{e.preventDefault();buildCM();cm.style.display='block';
        cm.style.left=Math.min(e.pageX,scrollX+innerWidth-200)+'px';
        cm.style.top=Math.min(e.pageY,scrollY+innerHeight-cm.scrollHeight-10)+'px';};
    const hideCM=()=>{cm.style.display='none';};

    // ── 클립보드 & 알림 ────────────────────────────────────────
    const execCopy=t=>{const x=el('textarea',{value:t});css(x,{position:'fixed',opacity:'0'});document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();};
    const clip=t=>navigator.clipboard?.writeText(t).catch(()=>execCopy(t))??execCopy(t);
    const confirm2=msg=>{const b=el('div',{textContent:msg});css(b,{position:'fixed',top:'50%',left:'50%',transform:'translate(-50%,-50%)',padding:'12px 20px',background:'#333',color:'#fff',borderRadius:'8px',fontFamily:'Arial,sans-serif',fontSize:'13px',zIndex:'2147483647',pointerEvents:'none',boxShadow:'0 4px 12px rgba(0,0,0,.3)'});document.body.appendChild(b);setTimeout(()=>b.remove(),2000);};

    // ── 이벤트 ─────────────────────────────────────────────────
    window.addEventListener('mousedown',e=>{if(e.button===1)showCM(e);});
    window.addEventListener('click',    e=>{if(!cm.contains(e.target))hideCM();});

})();
