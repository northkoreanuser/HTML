; ================================================================
; AES-256-GCM Library (libsodium wrapper)
; 사용법: #Include AES256GCM.ahk
; ================================================================

#NoEnv

global _AES_hLib := 0

; ── 자동 초기화 ───────────────────────────────────────────────────
_AES_AutoInit() {
    global _AES_hLib
    If (_AES_hLib)
        Return True
    Return AES_Init()
}

; ── 초기화 ───────────────────────────────────────────────────────
AES_Init(dllPath := "") {
    global _AES_hLib
    If (!dllPath)
        dllPath := A_ScriptDir . "\libsodium.dll"

    _AES_hLib := DllCall("LoadLibrary", "Str", dllPath, "Ptr")
    If (!_AES_hLib)
        Return False

    If (DllCall("libsodium\sodium_init") < 0)
        Return False

    If (!DllCall("libsodium\crypto_aead_aes256gcm_is_available", "Int"))
        Return False

    Return True
}

; ── 해제 ─────────────────────────────────────────────────────────
AES_Free() {
    global _AES_hLib
    If (_AES_hLib)
        DllCall("FreeLibrary", "Ptr", _AES_hLib)
    _AES_hLib := 0
}

; ── UTF-8 변환 ────────────────────────────────────────────────────
_AES_UTF8(str) {
    len := StrPut(str, "UTF-8")
    VarSetCapacity(buf, len, 0)
    StrPut(str, &buf, len, "UTF-8")
    Return buf
}

; ── 바이너리 → Hex ────────────────────────────────────────────────
_AES_BinToHex(ByRef bin, size) {
    VarSetCapacity(hex, size * 2 + 1, 0)
    DllCall("libsodium\sodium_bin2hex"
        , "Ptr",  &hex
        , "UPtr", size * 2 + 1
        , "Ptr",  &bin
        , "UPtr", size
        , "Ptr")
    Return StrGet(&hex, "UTF-8")
}

; ── Hex → 바이너리 ────────────────────────────────────────────────
_AES_HexToBin(hex, ByRef outBuf, size) {
    VarSetCapacity(outBuf, size, 0)
    hexBuf := _AES_UTF8(hex)
    DllCall("libsodium\sodium_hex2bin"
        , "Ptr",  &outBuf
        , "UPtr", size
        , "Ptr",  &hexBuf
        , "UPtr", StrLen(hex)
        , "Ptr",  0
        , "Ptr",  0
        , "Ptr",  0
        , "Int")
}

; ── 랜덤 키 생성 ──────────────────────────────────────────────────
AES_GenerateKey() {
    _AES_AutoInit()
    VarSetCapacity(buf, 32, 0)
    DllCall("libsodium\randombytes_buf", "Ptr", &buf, "UPtr", 32)
    Return buf
}

; ── 암호화 ───────────────────────────────────────────────────────
AES_Encrypt(ByRef key, plaintext) {
    _AES_AutoInit()

    NONCEBYTES := 12
    ABYTES     := 16
    KEYBYTES   := 32

    VarSetCapacity(nonce, NONCEBYTES, 0)
    DllCall("libsodium\randombytes_buf", "Ptr", &nonce, "UPtr", NONCEBYTES)

    VarSetCapacity(keyBuf, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", KEYBYTES)

    ptBuf  := _AES_UTF8(plaintext)
    ptLen  := StrPut(plaintext, "UTF-8") - 1
    ctLen  := ptLen + ABYTES
    VarSetCapacity(ctBuf, ctLen, 0)

    ret := DllCall("libsodium\crypto_aead_aes256gcm_encrypt"
        , "Ptr",    &ctBuf
        , "Ptr",    0
        , "Ptr",    &ptBuf
        , "UInt64", ptLen
        , "Ptr",    0
        , "UInt64", 0
        , "Ptr",    0
        , "Ptr",    &nonce
        , "Ptr",    &keyBuf
        , "Int")

    If (ret != 0)
        Return ""

    nonceHex := _AES_BinToHex(nonce, NONCEBYTES)
    ctHex    := _AES_BinToHex(ctBuf, ctLen)

    Return nonceHex . ":" . ctHex
}

; ── 복호화 ───────────────────────────────────────────────────────
AES_Decrypt(ByRef key, encrypted) {
    _AES_AutoInit()

    NONCEBYTES := 12
    ABYTES     := 16
    KEYBYTES   := 32

    colonPos := InStr(encrypted, ":")
    If (!colonPos)
        Return ""

    nonceHex := SubStr(encrypted, 1, colonPos - 1)
    ctHex    := SubStr(encrypted, colonPos + 1)

    ctLen := StrLen(ctHex) // 2
    ptLen := ctLen - ABYTES

    _AES_HexToBin(nonceHex, nonce, NONCEBYTES)
    _AES_HexToBin(ctHex, ctBuf, ctLen)

    VarSetCapacity(keyBuf, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", KEYBYTES)

    VarSetCapacity(ptBuf, ptLen + 1, 0)

    ret := DllCall("libsodium\crypto_aead_aes256gcm_decrypt"
        , "Ptr",    &ptBuf
        , "Ptr",    0
        , "Ptr",    0
        , "Ptr",    &ctBuf
        , "UInt64", ctLen
        , "Ptr",    0
        , "UInt64", 0
        , "Ptr",    &nonce
        , "Ptr",    &keyBuf
        , "Int")

    If (ret != 0)
        Return ""

    Return StrGet(&ptBuf, ptLen, "UTF-8")
}

; ── Argon2id 연계 암호화 ──────────────────────────────────────────
; 반환 : "saltHex|nonceHex:ciphertextHex"
AES_EncryptWithPassword(password, plaintext) {
    outSalt := ""
    key := Argon2id_DeriveKey(password, outSalt)
    If (key == "")
        Return ""

    saltHex := _AES_BinToHex(outSalt, 16)
    If (saltHex == "00000000000000000000000000000000")
        Return ""

    encrypted := AES_Encrypt(key, plaintext)
    If (encrypted == "")
        Return ""

    Return saltHex . "|" . encrypted
}

; ── Argon2id 연계 복호화 ──────────────────────────────────────────
; stored : AES_EncryptWithPassword() 반환값
AES_DecryptWithPassword(password, stored) {
    pipePos := InStr(stored, "|")
    If (!pipePos)
        Return ""

    saltHex   := SubStr(stored, 1, pipePos - 1)
    encrypted := SubStr(stored, pipePos + 1)

    SALTBYTES := 16
    VarSetCapacity(saltBuf, SALTBYTES, 0)
    saltUtf8 := _AES_UTF8(saltHex)
    DllCall("libsodium\sodium_hex2bin"
        , "Ptr",  &saltBuf
        , "UPtr", SALTBYTES
        , "Ptr",  &saltUtf8
        , "UPtr", StrLen(saltHex)
        , "Ptr",  0
        , "Ptr",  0
        , "Ptr",  0
        , "Int")

    outSalt := ""
    key := Argon2id_DeriveKey(password, outSalt, saltBuf)
    If (key == "")
        Return ""

    KEYBYTES := 32
    VarSetCapacity(keyBuf, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", KEYBYTES)

    Return AES_Decrypt(keyBuf, encrypted)
}