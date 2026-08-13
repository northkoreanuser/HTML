; ================================================================
; Argon2id Library (libargon2 wrapper) - 공식 참조 구현
; 사용법: #Include Argon2id.ahk
; 필요: libargon2.dll
;
; libargon2는 Argon2의 공식 C 참조 구현으로,
; 시간(t_cost), 메모리(m_cost), 병렬도(parallelism)를 모두 완전히 지원합니다.
; ================================================================

#NoEnv

global _Argon2id_OPSLIMIT := 3
global _Argon2id_MEMLIMIT := 64      ; MiB
global _Argon2id_PARALLEL  := 1
global _Argon2id_hLib      := 0

; ── 함수 포인터 ──────────────────────────────────────────────────
global _Argon2id_argon2id_hash_raw := 0
global _Argon2id_argon2_encodedlen := 0
global _Argon2id_argon2id_hash_encoded := 0
global _Argon2id_argon2id_verify := 0
global _Argon2id_argon2_error_message := 0

; ── 자동 초기화 ───────────────────────────────────────────────────
_Argon2id_AutoInit() {
    global _Argon2id_hLib
    If (_Argon2id_hLib)
        Return True
    Return Argon2id_Init()
}

; ── libargon2 초기화 ─────────────────────────────────────────────
Argon2id_Init(dllPath := "") {
    global _Argon2id_hLib
    global _Argon2id_argon2id_hash_raw, _Argon2id_argon2_encodedlen
    global _Argon2id_argon2id_hash_encoded, _Argon2id_argon2id_verify
    global _Argon2id_argon2_error_message

    If (!dllPath)
        dllPath := A_ScriptDir . "\libargon2.dll"

    _Argon2id_hLib := DllCall("LoadLibrary", "Str", dllPath, "Ptr")
    If (!_Argon2id_hLib) {
        ;MsgBox, libargon2.dll을 로드할 수 없습니다.`n`n파일이 스크립트와 같은 폴더에 있는지 확인하세요.
        Return False
    }

    ; libargon2 함수 로드
    _Argon2id_argon2id_hash_raw := DllCall("GetProcAddress", "Ptr", _Argon2id_hLib, "AStr", "argon2id_hash_raw", "Ptr")
    _Argon2id_argon2_encodedlen := DllCall("GetProcAddress", "Ptr", _Argon2id_hLib, "AStr", "argon2_encodedlen", "Ptr")
    _Argon2id_argon2id_hash_encoded := DllCall("GetProcAddress", "Ptr", _Argon2id_hLib, "AStr", "argon2id_hash_encoded", "Ptr")
    _Argon2id_argon2id_verify := DllCall("GetProcAddress", "Ptr", _Argon2id_hLib, "AStr", "argon2id_verify", "Ptr")
    _Argon2id_argon2_error_message := DllCall("GetProcAddress", "Ptr", _Argon2id_hLib, "AStr", "argon2_error_message", "Ptr")

    If (!_Argon2id_argon2id_hash_raw) {
        ;MsgBox, libargon2.dll에서 필요한 함수를 찾을 수 없습니다.`n`n올바른 버전의 libargon2.dll인지 확인하세요.
        DllCall("FreeLibrary", "Ptr", _Argon2id_hLib)
        _Argon2id_hLib := 0
        Return False
    }

    Return True
}

; ── 해제 ─────────────────────────────────────────────────────────
Argon2id_Free() {
    global _Argon2id_hLib
    If (_Argon2id_hLib) {
        DllCall("FreeLibrary", "Ptr", _Argon2id_hLib)
        _Argon2id_hLib := 0
    }
}

; ── 파라미터 설정 ─────────────────────────────────────────────────
Argon2id_SetParams(opslimit, memlimit, parallelism := 1) {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT, _Argon2id_PARALLEL
    _Argon2id_OPSLIMIT := opslimit
    _Argon2id_MEMLIMIT := memlimit  ; MiB 단위
    _Argon2id_PARALLEL := parallelism
}

; ── UTF-8 변환 ────────────────────────────────────────────────────
_Argon2id_UTF8(str) {
    len := StrPut(str, "UTF-8")
    VarSetCapacity(buf, len, 0)
    StrPut(str, &buf, len, "UTF-8")
    Return buf
}

; ── 키 파생 (raw 모드) ───────────────────────────────────────────
Argon2id_DeriveKey(password, ByRef outSalt, ByRef salt := "", opslimit := "", memlimit := "", parallelism := "") {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT, _Argon2id_PARALLEL
    global _Argon2id_argon2id_hash_raw, _Argon2id_argon2_error_message

    _Argon2id_AutoInit()

    If (opslimit == "")
        opslimit := _Argon2id_OPSLIMIT
    If (memlimit == "")
        memlimit := _Argon2id_MEMLIMIT
    If (parallelism == "")
        parallelism := _Argon2id_PARALLEL

    SALTBYTES := 16
    KEYBYTES := 32

    ; Salt 생성 또는 사용
    VarSetCapacity(saltBuf, SALTBYTES, 0)
    If (salt == "") {
        DllCall("advapi32\CryptGenRandom", "Ptr", 0, "UPtr", SALTBYTES, "Ptr", &saltBuf)
    } Else {
        DllCall("RtlMoveMemory", "Ptr", &saltBuf, "Ptr", &salt, "UPtr", SALTBYTES)
    }

    ; outSalt 반환
    VarSetCapacity(outSalt, SALTBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &outSalt, "Ptr", &saltBuf, "UPtr", SALTBYTES)

    ; Password UTF-8
    pwdBuf := _Argon2id_UTF8(password)
    pwdLen := StrPut(password, "UTF-8") - 1

    ; 키 버퍼
    VarSetCapacity(keyBuf, KEYBYTES, 0)

    ; libargon2: argon2id_hash_raw(
    ;   t_cost, m_cost (KiB), parallelism,
    ;   pwd, pwdlen, salt, saltlen, hash, hashlen
    ; )
    ; 반환값: 0 = 성공
    ret := DllCall(_Argon2id_argon2id_hash_raw
        , "UInt",   opslimit                    ; t_cost (시간 비용)
        , "UInt",   memlimit * 1024             ; m_cost (KiB)
        , "UInt",   parallelism                 ; parallelism (병렬도)
        , "Ptr",    &pwdBuf                     ; pwd
        , "UPtr",   pwdLen                      ; pwdlen
        , "Ptr",    &saltBuf                    ; salt
        , "UPtr",   SALTBYTES                   ; saltlen
        , "Ptr",    &keyBuf                     ; hash
        , "UPtr",   KEYBYTES                    ; hashlen
        , "Int")

    If (ret != 0) {
        ; 에러 메시지 가져오기
        errMsgPtr := DllCall(_Argon2id_argon2_error_message, "Int", ret, "Ptr")
        errMsg := StrGet(errMsgPtr, "UTF-8")
        ;MsgBox, argon2id_hash_raw 실패 (code %ret%): %errMsg%
        Return ""
    }

    ; 키 반환
    VarSetCapacity(keyOut, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyOut, "Ptr", &keyBuf, "UPtr", KEYBYTES)
    Return keyOut
}

; ── 해시 문자열 생성 (선택적) ────────────────────────────────────
Argon2id_Hash(password, opslimit := "", memlimit := "", parallelism := "") {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT, _Argon2id_PARALLEL
    global _Argon2id_argon2id_hash_encoded, _Argon2id_argon2_encodedlen
    global _Argon2id_argon2_error_message

    _Argon2id_AutoInit()

    If (opslimit == "")
        opslimit := _Argon2id_OPSLIMIT
    If (memlimit == "")
        memlimit := _Argon2id_MEMLIMIT
    If (parallelism == "")
        parallelism := _Argon2id_PARALLEL

    SALTBYTES := 16
    HASHBYTES := 32

    ; Salt 생성
    VarSetCapacity(saltBuf, SALTBYTES, 0)
    DllCall("advapi32\CryptGenRandom", "Ptr", 0, "UPtr", SALTBYTES, "Ptr", &saltBuf)

    ; Password UTF-8
    pwdBuf := _Argon2id_UTF8(password)
    pwdLen := StrPut(password, "UTF-8") - 1

    ; 인코딩된 해시 문자열 길이 계산
    encodedLen := DllCall(_Argon2id_argon2_encodedlen
        , "UInt", opslimit
        , "UInt", memlimit * 1024
        , "UInt", parallelism
        , "UInt", SALTBYTES
        , "UInt", HASHBYTES
        , "Int",  2  ; ARGON2_ID = 2
        , "Int")

    VarSetCapacity(encodedBuf, encodedLen, 0)

    ret := DllCall(_Argon2id_argon2id_hash_encoded
        , "UInt",   opslimit
        , "UInt",   memlimit * 1024
        , "UInt",   parallelism
        , "Ptr",    &pwdBuf
        , "UPtr",   pwdLen
        , "Ptr",    &saltBuf
        , "UPtr",   SALTBYTES
        , "UInt",   HASHBYTES
        , "Ptr",    &encodedBuf
        , "UPtr",   encodedLen
        , "Int",   2  ; ARGON2_ID = 2
        , "Int")

    If (ret != 0) {
        errMsgPtr := DllCall(_Argon2id_argon2_error_message, "Int", ret, "Ptr")
        errMsg := StrGet(errMsgPtr, "UTF-8")
        Return ""
    }

    Return StrGet(&encodedBuf, "UTF-8")
}

; ── 해시 검증 (선택적) ───────────────────────────────────────────
Argon2id_Verify(hash, password) {
    global _Argon2id_argon2id_verify, _Argon2id_argon2_error_message

    _Argon2id_AutoInit()

    pwdBuf := _Argon2id_UTF8(password)
    pwdLen := StrPut(password, "UTF-8") - 1

    hashBuf := _Argon2id_UTF8(hash)
    hashLen := StrPut(hash, "UTF-8") - 1

    ret := DllCall(_Argon2id_argon2id_verify
        , "Ptr",    &hashBuf
        , "Ptr",    &pwdBuf
        , "UPtr",   pwdLen
        , "Int",   2  ; ARGON2_ID = 2
        , "Int")

    Return (ret == 0)
}

; ── 단일 함수 인터페이스 ──────────────────────────────────────────
Argon2id(password, hash := "") {
    _Argon2id_AutoInit()
    Return (hash == "") ? Argon2id_Hash(password) : Argon2id_Verify(hash, password)
}