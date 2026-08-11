; ================================================================
; AES_FileEncrypt.ahk  —  파일 암호화/복호화 V1 (libsodium wrapper)
;
; ⚠ 레거시 모듈입니다. 신규 암호화는 AES_FileEncryptV2.ahk(SSB2_*)를
;   사용하세요. 이 모듈은 이 도구의 이전 버전으로 이미 만들어진 구버전
;   .Ssibal 파일을 계속 복호화할 수 있도록 하위 호환용으로만 남겨둔
;   것입니다 (전체 파일을 한 번에 메모리에 올리는 방식이라 대용량
;   파일에는 적합하지 않고, Argon2 파라미터도 파일에 저장되지 않습니다).
;
; 필요: AES256GCM.ahk, Argon2id.ahk, libsodium.dll
;
; 파일 포맷 (바이너리):
;   [2 bytes hint_len(LE)][hint_len bytes hint UTF-8]
;   [16 bytes salt][12 bytes nonce][N bytes ciphertext+tag(16)]
;
;   hint_len = 0 이면 힌트 없음 (하위 호환: 구버전 파일은 자동 감지)
;
; 사용:
;   #Include Argon2id.ahk
;   #Include AES256GCM.ahk
;   #Include AES_FileEncrypt.ahk
;
;   AES_EncryptFile("myPassword", "C:\photo.jpg", "C:\photo.jpg.Ssibal", "힌트 메모")
;   AES_DecryptFile("myPassword", "C:\photo.jpg.Ssibal", "C:\photo_dec.jpg")
;   hint := AES_ReadHint("C:\photo.jpg.Ssibal")   ; 힌트만 읽기 (복호화 불필요)
; ================================================================

#NoEnv

; ── 파일 암호화 ────────────────────────────────────────────────
; 성공 시 True, 실패 시 False 반환
; hint : 평문으로 저장되는 힌트 문자열 (선택, 기본값 "")
AES_EncryptFile(password, srcPath, dstPath, hint := "") {
    _AES_AutoInit()
    _Argon2id_AutoInit()

    SALTBYTES  := 16
    NONCEBYTES := 12
    ABYTES     := 16
    KEYBYTES   := 32

    ; ── 단계 1. 원본 파일 읽기 (바이너리) ─────────────────────
    fIn := FileOpen(srcPath, "r `n")   ; `n = 줄바꿈 변환 방지(바이너리)
    If (!IsObject(fIn)) {
        Return False
    }
    fileSize := fIn.Length
    If (fileSize <= 0) {
        fIn.Close()
        Return False
    }
    VarSetCapacity(plainBuf, fileSize, 0)
    fIn.RawRead(plainBuf, fileSize)
    fIn.Close()

    ; ── 단계 2. Argon2id 키 파생 (새 salt 생성) ───────────────
    outSalt := ""
    key     := Argon2id_DeriveKey(password, outSalt)
    If (key == "") {
        Return False
    }

    ; ── 단계 3. 랜덤 Nonce 생성 ───────────────────────────────
    VarSetCapacity(nonce, NONCEBYTES, 0)
    DllCall("libsodium\randombytes_buf", "Ptr", &nonce, "UPtr", NONCEBYTES)

    ; ── 단계 4. AES-256-GCM 암호화 ────────────────────────────
    VarSetCapacity(keyBuf, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", KEYBYTES)

    ctLen := fileSize + ABYTES
    VarSetCapacity(ctBuf, ctLen, 0)

    ret := DllCall("libsodium\crypto_aead_aes256gcm_encrypt"
        , "Ptr",    &ctBuf
        , "Ptr",    0
        , "Ptr",    &plainBuf
        , "UInt64", fileSize
        , "Ptr",    0
        , "UInt64", 0
        , "Ptr",    0
        , "Ptr",    &nonce
        , "Ptr",    &keyBuf
        , "Int")

    If (ret != 0) {
        Return False
    }

    ; ── 단계 5. 힌트를 UTF-8 바이트로 변환 ───────────────────
    ; AHK v1은 내부적으로 UTF-16. FileOpen으로 UTF-8 인코딩 변환 필요.
    ; StrPutStrGet 트릭으로 UTF-8 바이트열 얻기.
    hintBytes := ""
    hintLen   := 0
    If (hint != "") {
        hintLen := StrPut(hint, "UTF-8") - 1   ; -1 : null terminator 제외
        VarSetCapacity(hintBuf, hintLen + 1, 0)
        StrPut(hint, &hintBuf, hintLen + 1, "UTF-8")
        hintBytes := hintLen
    }

    ; ── 단계 6. 출력 파일 쓰기 ────────────────────────────────
    ; 포맷: [2 bytes hint_len LE][hint UTF-8][16 salt][12 nonce][ciphertext]
    fOut := FileOpen(dstPath, "w `n")
    If (!IsObject(fOut)) {
        Return False
    }

    ; hint_len (2 bytes, little-endian)
    VarSetCapacity(hlenBuf, 2, 0)
    NumPut(hintLen & 0xFFFF, hlenBuf, 0, "UShort")
    fOut.RawWrite(hlenBuf, 2)

    ; hint 본문 (hintLen bytes)
    If (hintLen > 0)
        fOut.RawWrite(hintBuf, hintLen)

    ; salt, nonce, ciphertext
    fOut.RawWrite(outSalt, SALTBYTES)
    fOut.RawWrite(nonce,   NONCEBYTES)
    fOut.RawWrite(ctBuf,   ctLen)
    fOut.Close()

    Return True
}

; ── 파일 복호화 ────────────────────────────────────────────────
; 성공 시 True, 실패 시 False 반환
AES_DecryptFile(password, srcPath, dstPath) {
    _AES_AutoInit()
    _Argon2id_AutoInit()

    SALTBYTES  := 16
    NONCEBYTES := 12
    ABYTES     := 16
    KEYBYTES   := 32

    ; ── 단계 1. 암호화된 파일 읽기 ────────────────────────────
    fIn := FileOpen(srcPath, "r `n")
    If (!IsObject(fIn)) {
        Return False
    }
    totalSize := fIn.Length

    ; 최소 크기 체크: 2(hint_len) + 0(hint) + 16(salt) + 12(nonce) + 16(tag) = 46
    If (totalSize < 46) {
        fIn.Close()
        Return False
    }

    ; hint_len 읽기 (2 bytes)
    VarSetCapacity(hlenBuf, 2, 0)
    fIn.RawRead(hlenBuf, 2)
    hintLen := NumGet(hlenBuf, 0, "UShort")

    ; 구버전 파일 호환: hint_len이 비정상적으로 크면(>= 4096) 구포맷으로 간주
    ; 구포맷: 첫 2바이트가 salt의 첫 2바이트이므로 hintLen이 우연히 맞을 수 있음
    ; → 구포맷은 2바이트 hint_len 필드가 없으므로 전체 크기 기반으로 판별
    ; 신뢰할 수 있는 방법: hintLen < 4096 && totalSize >= 2 + hintLen + 16 + 12 + 16
    minSize := 2 + hintLen + SALTBYTES + NONCEBYTES + ABYTES
    If (hintLen >= 4096 || totalSize < minSize) {
        ; 구버전 파일로 간주 — hint_len 필드 없이 [salt][nonce][ct] 형식
        fIn.Seek(0)
        hintLen  := 0
    }

    ; hint 건너뜀 (이미 읽었거나 seek 후 0)
    If (hintLen > 0) {
        VarSetCapacity(hintSkip, hintLen, 0)
        fIn.RawRead(hintSkip, hintLen)
    }

    ; 남은 크기 계산
    HEADER := SALTBYTES + NONCEBYTES   ; 28 bytes
    remaining := fIn.Length - fIn.Pos
    If (remaining <= HEADER + ABYTES) {
        fIn.Close()
        Return False
    }

    VarSetCapacity(saltBuf,  SALTBYTES,  0)
    VarSetCapacity(nonce,    NONCEBYTES, 0)
    ctLen := remaining - HEADER
    VarSetCapacity(ctBuf, ctLen, 0)

    fIn.RawRead(saltBuf, SALTBYTES)
    fIn.RawRead(nonce,   NONCEBYTES)
    fIn.RawRead(ctBuf,   ctLen)
    fIn.Close()

    ; ── 단계 2. Argon2id 키 파생 (저장된 salt 사용) ───────────
    outSalt := ""
    key     := Argon2id_DeriveKey(password, outSalt, saltBuf)
    If (key == "") {
        Return False
    }

    ; ── 단계 3. AES-256-GCM 복호화 ────────────────────────────
    VarSetCapacity(keyBuf, KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", KEYBYTES)

    ptLen := ctLen - ABYTES
    VarSetCapacity(ptBuf, ptLen, 0)

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

    If (ret != 0) {
        Return False
    }

    ; ── 단계 4. 복호화된 데이터 저장 ─────────────────────────
    fOut := FileOpen(dstPath, "w `n")
    If (!IsObject(fOut)) {
        Return False
    }
    fOut.RawWrite(ptBuf, ptLen)
    fOut.Close()

    Return True
}

; ── 힌트만 읽기 (복호화 불필요) ───────────────────────────────
; 힌트가 없거나 구버전 파일이면 "" 반환
AES_ReadHint(srcPath) {
    fIn := FileOpen(srcPath, "r `n")
    If (!IsObject(fIn))
        Return ""

    totalSize := fIn.Length
    If (totalSize < 46) {
        fIn.Close()
        Return ""
    }

    ; hint_len 읽기 (2 bytes LE)
    VarSetCapacity(hlenBuf, 2, 0)
    fIn.RawRead(hlenBuf, 2)
    hintLen := NumGet(hlenBuf, 0, "UShort")

    ; 구버전 or 힌트 없음
    If (hintLen = 0 || hintLen >= 4096) {
        fIn.Close()
        Return ""
    }

    ; 크기 유효성 체크
    If (totalSize < 2 + hintLen + 16 + 12 + 16) {
        fIn.Close()
        Return ""
    }

    ; hint 바이트 읽기
    VarSetCapacity(hintBuf, hintLen + 1, 0)
    fIn.RawRead(hintBuf, hintLen)
    fIn.Close()

    ; UTF-8 → AHK 문자열 변환
    hint := StrGet(&hintBuf, hintLen, "UTF-8")
    Return hint
}

; ── 편의 함수: 암호화 후 원본 삭제 ───────────────────────────
AES_EncryptFileAndDelete(password, srcPath, dstPath := "", hint := "") {
    If (dstPath == "")
        dstPath := srcPath . ".Ssibal"

    If (!AES_EncryptFile(password, srcPath, dstPath, hint))
        Return False

    FileDelete, %srcPath%
    Return True
}

; ── 편의 함수: 복호화 후 암호화 파일 삭제 ────────────────────
AES_DecryptFileAndDelete(password, srcPath, dstPath := "") {
    If (dstPath == "") {
        If (SubStr(srcPath, -6) == ".Ssibal")
            dstPath := SubStr(srcPath, 1, StrLen(srcPath) - 7)
        Else If (SubStr(srcPath, -3) == ".enc")
            dstPath := SubStr(srcPath, 1, StrLen(srcPath) - 4)
        Else
            dstPath := srcPath . "_dec"
    }

    If (!AES_DecryptFile(password, srcPath, dstPath))
        Return False

    FileDelete, %srcPath%
    Return True
}
