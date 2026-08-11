; ================================================================
; Argon2id Library (libsodium wrapper)
; 사용법: #Include Argon2id.ahk
; ================================================================

#NoEnv

global _Argon2id_OPSLIMIT := 3
global _Argon2id_MEMLIMIT := 67108864  ; 64MB
global _Argon2id_hLib     := 0

; ── 자동 초기화 ───────────────────────────────────────────────────
_Argon2id_AutoInit() {
    global _Argon2id_hLib
    If (_Argon2id_hLib)
        Return True
    Return Argon2id_Init()
}

; ── 초기화 ───────────────────────────────────────────────────────
Argon2id_Init(dllPath := "") {
    global _Argon2id_hLib
    If (!dllPath)
        dllPath := A_ScriptDir . "\libsodium.dll"

    _Argon2id_hLib := DllCall("LoadLibrary", "Str", dllPath, "Ptr")
    If (!_Argon2id_hLib)
        Return False

    If (DllCall("libsodium\sodium_init") < 0)
        Return False

    Return True
}

; ── 해제 ─────────────────────────────────────────────────────────
Argon2id_Free() {
    global _Argon2id_hLib
    If (_Argon2id_hLib)
        DllCall("FreeLibrary", "Ptr", _Argon2id_hLib)
    _Argon2id_hLib := 0
}

; ── 파라미터 설정 ─────────────────────────────────────────────────
Argon2id_SetParams(opslimit, memlimit) {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT
    _Argon2id_OPSLIMIT := opslimit
    _Argon2id_MEMLIMIT := memlimit
}

; ── UTF-8 변환 ────────────────────────────────────────────────────
_Argon2id_UTF8(str) {
    len := StrPut(str, "UTF-8")
    VarSetCapacity(buf, len, 0)
    StrPut(str, &buf, len, "UTF-8")
    Return buf
}

; ── 해시 생성 ─────────────────────────────────────────────────────
Argon2id_Hash(password, opslimit := "", memlimit := "") {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT
    _Argon2id_AutoInit()

    If (opslimit == "")
        opslimit := _Argon2id_OPSLIMIT
    If (memlimit == "")
        memlimit := _Argon2id_MEMLIMIT

    STRBYTES := 128
    buf    := _Argon2id_UTF8(password)
    pwdLen := StrPut(password, "UTF-8") - 1
    VarSetCapacity(hashOut, STRBYTES, 0)

    ret := DllCall("libsodium\crypto_pwhash_str"
        , "Ptr",    &hashOut
        , "Ptr",    &buf
        , "UInt64", pwdLen
        , "UInt64", opslimit
        , "UPtr",   memlimit
        , "Int")

    Return (ret == 0) ? StrGet(&hashOut, STRBYTES, "UTF-8") : ""
}

; ── 해시 검증 ─────────────────────────────────────────────────────
Argon2id_Verify(hash, password) {
    _Argon2id_AutoInit()
    STRBYTES := 128

    pwdBuf := _Argon2id_UTF8(password)
    pwdLen := StrPut(password, "UTF-8") - 1

    VarSetCapacity(hashBuf, STRBYTES, 0)
    StrPut(hash, &hashBuf, STRBYTES, "UTF-8")

    ret := DllCall("libsodium\crypto_pwhash_str_verify"
        , "Ptr",    &hashBuf
        , "Ptr",    &pwdBuf
        , "UInt64", pwdLen
        , "Int")

    Return (ret == 0)
}

; ── 재해싱 필요 여부 ──────────────────────────────────────────────
Argon2id_NeedsRehash(hash, opslimit := "", memlimit := "") {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT
    _Argon2id_AutoInit()

    If (opslimit == "")
        opslimit := _Argon2id_OPSLIMIT
    If (memlimit == "")
        memlimit := _Argon2id_MEMLIMIT

    STRBYTES := 128
    VarSetCapacity(hashBuf, STRBYTES, 0)
    StrPut(hash, &hashBuf, STRBYTES, "UTF-8")

    ret := DllCall("libsodium\crypto_pwhash_str_needs_rehash"
        , "Ptr",    &hashBuf
        , "UInt64", opslimit
        , "UPtr",   memlimit
        , "Int")

    Return (ret == 1)
}

; ── 키 파생 (raw 모드, AES 연계용) ───────────────────────────────
Argon2id_DeriveKey(password, ByRef outSalt, ByRef salt := "", opslimit := "", memlimit := "") {
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT
    _Argon2id_AutoInit()

    If (opslimit == "")
        opslimit := _Argon2id_OPSLIMIT
    If (memlimit == "")
        memlimit := _Argon2id_MEMLIMIT

    SALTBYTES      := 16
    KEYBYTES       := 32
    ALG_ARGON2ID13 := 2

    VarSetCapacity(saltBuf, SALTBYTES, 0)

    If (salt == "") {
        DllCall("libsodium\randombytes_buf", "Ptr", &saltBuf, "UPtr", SALTBYTES)
    } Else {
        DllCall("RtlMoveMemory", "Ptr", &saltBuf, "Ptr", &salt, "UPtr", SALTBYTES)
    }

    VarSetCapacity(outSalt, SALTBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &outSalt, "Ptr", &saltBuf, "UPtr", SALTBYTES)

    pwdBuf := _Argon2id_UTF8(password)
    pwdLen := StrPut(password, "UTF-8") - 1

    VarSetCapacity(keyBuf, KEYBYTES, 0)

    ret := DllCall("libsodium\crypto_pwhash"
        , "Ptr",    &keyBuf
        , "UInt64", KEYBYTES
        , "Ptr",    &pwdBuf
        , "UInt64", pwdLen
        , "Ptr",    &saltBuf
        , "UInt64", opslimit
        , "UPtr",   memlimit
        , "Int",    ALG_ARGON2ID13
        , "Int")

    If (ret != 0)
        Return ""

    VarSetCapacity(keyOut, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyOut, "Ptr", &keyBuf, "UPtr", KEYBYTES)

    Return keyOut
}

; ── 로그인 처리 (검증 + 재해싱 통합) ─────────────────────────────
Argon2id_Login(storedHash, inputPassword) {
    result := Object()
    result.ok         := False
    result.newHash    := ""
    result.needRehash := False

    If (!Argon2id_Verify(storedHash, inputPassword))
        Return result

    result.ok := True

    If (Argon2id_NeedsRehash(storedHash)) {
        result.needRehash := True
        result.newHash    := Argon2id_Hash(inputPassword)
    }

    Return result
}

; ── 단일 함수 인터페이스 ──────────────────────────────────────────
; hash 없으면 생성, 있으면 검증
Argon2id(password, hash := "") {
    _Argon2id_AutoInit()
    Return (hash == "") ? Argon2id_Hash(password) : Argon2id_Verify(hash, password)
}