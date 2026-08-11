; ================================================================
; AES_FileEncryptV2.ahk — 파일 암호화/복호화 (봉투 암호화 + 스트리밍)
; 필요: AES256GCM.ahk, Argon2id.ahk, libsodium.dll
;
; nykenc.pyw(파이썬판)와 동일한 설계 철학을 AutoHotkey로 이식한 버전입니다.
;
; 특징
; ------------------
;   1) 대용량 파일 스트리밍: 4MB 청크 단위로 나눠 처리 → 수십 GB 파일도
;      한 번에 메모리에 올리지 않고 암/복호화 가능.
;   2) 봉투 암호화(envelope encryption): 파일마다 랜덤 256비트 FEK(파일
;      암호화 키)를 생성해서 실제 데이터는 FEK로 암호화하고, 그 FEK를
;      패스워드로부터 Argon2id로 유도한 KEK로 다시 래핑해서 저장합니다.
;   3) Argon2id 파라미터(ops/mem)와 salt를 파일 헤더에 그대로 저장 →
;      나중에 이 스크립트의 기본값(Argon2id_SetParams)이 바뀌어도 예전
;      파일은 저장된 자기 파라미터로 문제없이 열립니다.
;   4) AAD(추가 인증 데이터) 바인딩:
;        - 청크마다 청크 인덱스 + is_last 플래그(마지막 청크 여부)를
;          AAD로 묶어서, 암호문 청크를 다른 위치로 옮기거나 다른 파일의
;          청크와 바꿔치기하는 재배열/치환 공격뿐 아니라, 파일 뒤쪽
;          청크를 잘라내고 chunk_count만 줄이는 절단(truncation) 공격도
;          막습니다 — 잘린 결과물의 "새 마지막 청크"는 원래 is_last=0로
;          암호화됐던 청크라 AAD 불일치로 태그 검증이 실패합니다.
;        - FEK 래핑 단계에도 헤더(매직+salt+Argon2 파라미터)를 AAD로
;          묶어서, salt/파라미터를 몰래 바꿔서 KDF 비용을 낮추는 다운
;          그레이드 공격을 막습니다.
;   5) 원자적 쓰기: 목적 파일과 같은 폴더의 임시 파일에 먼저 다 쓴 뒤
;      MoveFileEx(REPLACE_EXISTING)로 한 번에 교체 → 중간에 실패해도
;      기존 파일이 손상되지 않습니다.
;   6) 민감한 버퍼(키/평문) 제로화: 다 쓴 직후 RtlFillMemory로 덮어씁니다
;      (베스트 에포트 조치입니다 - VarSetCapacity 특성상 100% 보장은 아님).
;
; 파일 포맷 (전부 네이티브 리틀 엔디안):
;   [8]  magic "SSIBALV2"
;   [2]  hint_len (UShort)
;   [hint_len] hint (UTF-8)
;   [16] Argon2id salt
;   [4]  Argon2id opslimit (UInt, 시간 비용)
;   [8]  Argon2id memlimit (Int64, 바이트 단위 메모리 비용)
;   [12] wrap_nonce (FEK 래핑용)
;   [2]  wrapped_key_len (UShort, 보통 48 = 32+16)
;   [wrapped_key_len] wrapped FEK
;   [8]  chunk_count (Int64)
;   청크 * chunk_count:
;     [12] chunk_nonce
;     [4]  ciphertext_len (UInt, GCM 태그 16바이트 포함)
;     [ciphertext_len] ciphertext
;
; 사용:
;   #Include Argon2id.ahk
;   #Include AES256GCM.ahk
;   #Include AES_FileEncryptV2.ahk
;
;   SSB2_EncryptFile("pw", "C:\big.mp4", "C:\big.mp4.Ssibal", "힌트")
;   SSB2_DecryptFile("pw", "C:\big.mp4.Ssibal", "C:\big_dec.mp4")
;   SSB2_IsV2File("C:\big.mp4.Ssibal")   ; 매직 헤더로 포맷 여부 판별
; ================================================================

#NoEnv

global SSB2_MAGIC      := "SSIBALV2"
global SSB2_CHUNK_SIZE := 4194304        ; 4MB
global SSB2_SALTBYTES  := 16
global SSB2_NONCEBYTES := 12
global SSB2_ABYTES     := 16
global SSB2_KEYBYTES   := 32

; ── 메모리 제로화 (best-effort) ──────────────────────────────────
_SSB2_ZeroMem(ByRef buf, size) {
    If (size > 0)
        DllCall("RtlFillMemory", "Ptr", &buf, "UPtr", size, "UChar", 0)
}

; ── 매직 헤더만으로 V2 포맷 여부 판별 ─────────────────────────────
SSB2_IsV2File(path) {
    global SSB2_MAGIC
    fIn := FileOpen(path, "r `n")
    If (!IsObject(fIn))
        Return False
    If (fIn.Length < 8) {
        fIn.Close()
        Return False
    }
    VarSetCapacity(magicBuf, 8, 0)
    fIn.RawRead(magicBuf, 8)
    fIn.Close()
    Return (StrGet(&magicBuf, 8, "UTF-8") = SSB2_MAGIC)
}

; ── 힌트만 읽기 (복호화 불필요) ───────────────────────────────────
SSB2_ReadHint(path) {
    global SSB2_MAGIC
    fIn := FileOpen(path, "r `n")
    If (!IsObject(fIn))
        Return ""
    If (fIn.Length < 10) {
        fIn.Close()
        Return ""
    }
    VarSetCapacity(magicBuf, 8, 0)
    fIn.RawRead(magicBuf, 8)
    If (StrGet(&magicBuf, 8, "UTF-8") != SSB2_MAGIC) {
        fIn.Close()
        Return ""
    }
    VarSetCapacity(hlenBuf, 2, 0)
    fIn.RawRead(hlenBuf, 2)
    hintLen := NumGet(hlenBuf, 0, "UShort")
    If (hintLen = 0 || fIn.Length < 10 + hintLen) {
        fIn.Close()
        Return ""
    }
    VarSetCapacity(hintBuf, hintLen, 0)
    fIn.RawRead(hintBuf, hintLen)
    fIn.Close()
    Return StrGet(&hintBuf, hintLen, "UTF-8")
}

; ── 헤더의 Argon2 파라미터 미리읽기 (복호화 전 참고 표시용, 선택) ──
SSB2_PeekParams(path) {
    global SSB2_MAGIC, SSB2_SALTBYTES
    result := Object()
    result.ok := False

    fIn := FileOpen(path, "r `n")
    If (!IsObject(fIn))
        Return result

    VarSetCapacity(magicBuf, 8, 0)
    fIn.RawRead(magicBuf, 8)
    If (StrGet(&magicBuf, 8, "UTF-8") != SSB2_MAGIC) {
        fIn.Close()
        Return result
    }

    VarSetCapacity(hlenBuf, 2, 0)
    fIn.RawRead(hlenBuf, 2)
    hintLen := NumGet(hlenBuf, 0, "UShort")
    If (hintLen > 0) {
        VarSetCapacity(skipBuf, hintLen, 0)
        fIn.RawRead(skipBuf, hintLen)
    }

    VarSetCapacity(saltBuf, SSB2_SALTBYTES, 0)
    fIn.RawRead(saltBuf, SSB2_SALTBYTES)

    VarSetCapacity(paramBuf, 12, 0)
    fIn.RawRead(paramBuf, 12)
    fIn.Close()

    result.ok       := True
    result.opslimit := NumGet(paramBuf, 0, "UInt")
    result.memlimit := NumGet(paramBuf, 4, "Int64")
    Return result
}

; ── 파일 암호화 (V2, 스트리밍) ────────────────────────────────────
; opslimit/memlimit을 비워두면 Argon2id.ahk의 현재 전역 기본값을 사용
; progressCb : 진행률 콜백 함수 이름(문자열). Call(progressCb, done, total)
;              형태로 청크마다(부하를 줄이기 위해 일정 간격으로) 호출됨.
;              비워두면 호출 없이 조용히 처리.
SSB2_EncryptFile(password, srcPath, dstPath, hint := "", opslimit := "", memlimit := "", progressCb := "") {
    global SSB2_MAGIC, SSB2_CHUNK_SIZE, SSB2_SALTBYTES, SSB2_NONCEBYTES, SSB2_ABYTES, SSB2_KEYBYTES
    global _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT

    _AES_AutoInit()
    _Argon2id_AutoInit()

    If (opslimit = "")
        opslimit := _Argon2id_OPSLIMIT
    If (memlimit = "")
        memlimit := _Argon2id_MEMLIMIT

    ; ── 원본 파일 크기만 미리 확인 (실제 읽기는 청크 단위로) ──────
    fInCheck := FileOpen(srcPath, "r `n")
    If (!IsObject(fInCheck))
        Return False
    fileSize := fInCheck.Length
    fInCheck.Close()

    chunkCount := (fileSize <= 0) ? 1 : Ceil(fileSize / SSB2_CHUNK_SIZE)

    ; ── FEK(파일 암호화 키) 생성 ───────────────────────────────
    VarSetCapacity(fek, SSB2_KEYBYTES, 0)
    DllCall("libsodium\randombytes_buf", "Ptr", &fek, "UPtr", SSB2_KEYBYTES)

    ; ── KEK 유도 (Argon2id, 새 salt 생성) ─────────────────────
    outSalt := ""
    kek := Argon2id_DeriveKey(password, outSalt, "", opslimit, memlimit)
    If (kek = "") {
        _SSB2_ZeroMem(fek, SSB2_KEYBYTES)
        Return False
    }
    VarSetCapacity(kekBuf, SSB2_KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &kekBuf, "Ptr", &kek, "UPtr", SSB2_KEYBYTES)

    ; ── 래핑용 AAD = magic . salt . opslimit . memlimit ───────
    wrapAadLen := 8 + SSB2_SALTBYTES + 4 + 8
    VarSetCapacity(wrapAad, wrapAadLen, 0)
    StrPut(SSB2_MAGIC, &wrapAad, 9, "UTF-8")
    DllCall("RtlMoveMemory", "Ptr", &wrapAad + 8, "Ptr", &outSalt, "UPtr", SSB2_SALTBYTES)
    NumPut(opslimit, wrapAad, 8 + SSB2_SALTBYTES, "UInt")
    NumPut(memlimit, wrapAad, 8 + SSB2_SALTBYTES + 4, "Int64")

    ; ── wrap_nonce 생성 & FEK 래핑(AES-256-GCM) ───────────────
    VarSetCapacity(wrapNonce, SSB2_NONCEBYTES, 0)
    DllCall("libsodium\randombytes_buf", "Ptr", &wrapNonce, "UPtr", SSB2_NONCEBYTES)

    wrappedLen := SSB2_KEYBYTES + SSB2_ABYTES
    VarSetCapacity(wrappedBuf, wrappedLen, 0)

    ret := DllCall("libsodium\crypto_aead_aes256gcm_encrypt"
        , "Ptr",    &wrappedBuf
        , "Ptr",    0
        , "Ptr",    &fek
        , "UInt64", SSB2_KEYBYTES
        , "Ptr",    &wrapAad
        , "UInt64", wrapAadLen
        , "Ptr",    0
        , "Ptr",    &wrapNonce
        , "Ptr",    &kekBuf
        , "Int")

    _SSB2_ZeroMem(kekBuf, SSB2_KEYBYTES)
    _SSB2_ZeroMem(wrapAad, wrapAadLen)

    If (ret != 0) {
        _SSB2_ZeroMem(fek, SSB2_KEYBYTES)
        Return False
    }

    ; ── 힌트 UTF-8 인코딩 ──────────────────────────────────────
    hintLen := 0
    If (hint != "") {
        hintLen := StrPut(hint, "UTF-8") - 1
        VarSetCapacity(hintBuf, hintLen, 0)
        StrPut(hint, &hintBuf, hintLen + 1, "UTF-8")
    }

    ; ── 목적 폴더의 임시 파일에 스트리밍으로 쓰기 ─────────────
    tmpPath := _SSB2_TempPathFor(dstPath)
    fOut := FileOpen(tmpPath, "w `n")
    If (!IsObject(fOut)) {
        _SSB2_ZeroMem(fek, SSB2_KEYBYTES)
        Return False
    }

    ok := True
    fIn := ""
    Try {
        _SSB2_WriteStr8(fOut, SSB2_MAGIC)

        VarSetCapacity(hlenBuf, 2, 0)
        NumPut(hintLen & 0xFFFF, hlenBuf, 0, "UShort")
        fOut.RawWrite(hlenBuf, 2)
        If (hintLen > 0)
            fOut.RawWrite(hintBuf, hintLen)

        fOut.RawWrite(outSalt, SSB2_SALTBYTES)

        VarSetCapacity(paramBuf, 12, 0)
        NumPut(opslimit, paramBuf, 0, "UInt")
        NumPut(memlimit, paramBuf, 4, "Int64")
        fOut.RawWrite(paramBuf, 12)

        fOut.RawWrite(wrapNonce, SSB2_NONCEBYTES)

        VarSetCapacity(wlenBuf, 2, 0)
        NumPut(wrappedLen & 0xFFFF, wlenBuf, 0, "UShort")
        fOut.RawWrite(wlenBuf, 2)
        fOut.RawWrite(wrappedBuf, wrappedLen)

        VarSetCapacity(ccBuf, 8, 0)
        NumPut(chunkCount, ccBuf, 0, "Int64")
        fOut.RawWrite(ccBuf, 8)

        ; ── 청크 스트리밍 암호화 ───────────────────────────────
        VarSetCapacity(plainBuf, SSB2_CHUNK_SIZE, 0)
        VarSetCapacity(ctBuf, SSB2_CHUNK_SIZE + SSB2_ABYTES, 0)

        fIn := FileOpen(srcPath, "r `n")
        If (!IsObject(fIn))
            Throw Exception("원본 파일을 열 수 없습니다.")

        Loop %chunkCount% {
            idx := A_Index - 1
            readLen := fIn.RawRead(plainBuf, SSB2_CHUNK_SIZE)

            VarSetCapacity(chunkNonce, SSB2_NONCEBYTES, 0)
            DllCall("libsodium\randombytes_buf", "Ptr", &chunkNonce, "UPtr", SSB2_NONCEBYTES)

            VarSetCapacity(idxAad, 9, 0)
            NumPut(idx, idxAad, 0, "Int64")
            isLast := (A_Index = chunkCount) ? 1 : 0
            NumPut(isLast, idxAad, 8, "UChar")

            ctLen := readLen + SSB2_ABYTES
            ret := DllCall("libsodium\crypto_aead_aes256gcm_encrypt"
                , "Ptr",    &ctBuf
                , "Ptr",    0
                , "Ptr",    &plainBuf
                , "UInt64", readLen
                , "Ptr",    &idxAad
                , "UInt64", 9
                , "Ptr",    0
                , "Ptr",    &chunkNonce
                , "Ptr",    &fek
                , "Int")

            If (ret != 0)
                Throw Exception("청크 " . idx . " 암호화 실패.")

            fOut.RawWrite(chunkNonce, SSB2_NONCEBYTES)
            VarSetCapacity(clenBuf, 4, 0)
            NumPut(ctLen, clenBuf, 0, "UInt")
            fOut.RawWrite(clenBuf, 4)
            fOut.RawWrite(ctBuf, ctLen)

            _SSB2_ZeroMem(plainBuf, readLen)
            _SSB2_ZeroMem(ctBuf, ctLen)

            If (progressCb != "" && (Mod(A_Index, 4) = 0 || A_Index = chunkCount)) {
                %progressCb%(A_Index, chunkCount)
                Sleep -1   ; 메시지 펌프 (UI 응답성 유지)
            }
        }

        fIn.Close()
        fIn := ""
        fOut.Close()
    } Catch e {
        ok := False
        If IsObject(fIn)
            Try fIn.Close()
        Try fOut.Close()
    }

    _SSB2_ZeroMem(fek, SSB2_KEYBYTES)
    If (hintLen > 0)
        _SSB2_ZeroMem(hintBuf, hintLen)

    If (!ok) {
        FileDelete, %tmpPath%
        Return False
    }

    Return _SSB2_AtomicCommit(tmpPath, dstPath)
}

; ── 파일 복호화 (V2, 스트리밍) ────────────────────────────────────
SSB2_DecryptFile(password, srcPath, dstPath, progressCb := "") {
    global SSB2_MAGIC, SSB2_CHUNK_SIZE, SSB2_SALTBYTES, SSB2_NONCEBYTES, SSB2_ABYTES, SSB2_KEYBYTES

    _AES_AutoInit()
    _Argon2id_AutoInit()

    fIn := FileOpen(srcPath, "r `n")
    If (!IsObject(fIn))
        Return False

    VarSetCapacity(magicBuf, 8, 0)
    fIn.RawRead(magicBuf, 8)
    If (StrGet(&magicBuf, 8, "UTF-8") != SSB2_MAGIC) {
        fIn.Close()
        Return False
    }

    VarSetCapacity(hlenBuf, 2, 0)
    fIn.RawRead(hlenBuf, 2)
    hintLen := NumGet(hlenBuf, 0, "UShort")
    If (hintLen > 0) {
        VarSetCapacity(skipBuf, hintLen, 0)
        fIn.RawRead(skipBuf, hintLen)
    }

    VarSetCapacity(saltBuf, SSB2_SALTBYTES, 0)
    fIn.RawRead(saltBuf, SSB2_SALTBYTES)

    VarSetCapacity(paramBuf, 12, 0)
    fIn.RawRead(paramBuf, 12)
    opslimit := NumGet(paramBuf, 0, "UInt")
    memlimit := NumGet(paramBuf, 4, "Int64")

    VarSetCapacity(wrapNonce, SSB2_NONCEBYTES, 0)
    fIn.RawRead(wrapNonce, SSB2_NONCEBYTES)

    VarSetCapacity(wlenBuf, 2, 0)
    fIn.RawRead(wlenBuf, 2)
    wrappedLen := NumGet(wlenBuf, 0, "UShort")
    VarSetCapacity(wrappedBuf, wrappedLen, 0)
    fIn.RawRead(wrappedBuf, wrappedLen)

    VarSetCapacity(ccBuf, 8, 0)
    fIn.RawRead(ccBuf, 8)
    chunkCount := NumGet(ccBuf, 0, "Int64")

    ; ── KEK 재유도 (저장된 salt/파라미터 그대로 사용) ─────────
    outSalt := ""
    kek := Argon2id_DeriveKey(password, outSalt, saltBuf, opslimit, memlimit)
    If (kek = "") {
        fIn.Close()
        Return False
    }
    VarSetCapacity(kekBuf, SSB2_KEYBYTES, 0)
    DllCall("RtlMoveMemory", "Ptr", &kekBuf, "Ptr", &kek, "UPtr", SSB2_KEYBYTES)

    ; ── 래핑 AAD 재구성 (암호화 때와 정확히 같아야 태그 검증 통과) ──
    wrapAadLen := 8 + SSB2_SALTBYTES + 4 + 8
    VarSetCapacity(wrapAad, wrapAadLen, 0)
    StrPut(SSB2_MAGIC, &wrapAad, 9, "UTF-8")
    DllCall("RtlMoveMemory", "Ptr", &wrapAad + 8, "Ptr", &saltBuf, "UPtr", SSB2_SALTBYTES)
    NumPut(opslimit, wrapAad, 8 + SSB2_SALTBYTES, "UInt")
    NumPut(memlimit, wrapAad, 8 + SSB2_SALTBYTES + 4, "Int64")

    VarSetCapacity(fek, SSB2_KEYBYTES, 0)
    ret := DllCall("libsodium\crypto_aead_aes256gcm_decrypt"
        , "Ptr",    &fek
        , "Ptr",    0
        , "Ptr",    0
        , "Ptr",    &wrappedBuf
        , "UInt64", wrappedLen
        , "Ptr",    &wrapAad
        , "UInt64", wrapAadLen
        , "Ptr",    &wrapNonce
        , "Ptr",    &kekBuf
        , "Int")

    _SSB2_ZeroMem(kekBuf, SSB2_KEYBYTES)
    _SSB2_ZeroMem(wrapAad, wrapAadLen)

    If (ret != 0) {
        ; 패스워드가 틀렸거나 파일이 손상/변조된 경우
        fIn.Close()
        _SSB2_ZeroMem(fek, SSB2_KEYBYTES)
        Return False
    }

    tmpPath := _SSB2_TempPathFor(dstPath)
    fOut := FileOpen(tmpPath, "w `n")
    If (!IsObject(fOut)) {
        fIn.Close()
        _SSB2_ZeroMem(fek, SSB2_KEYBYTES)
        Return False
    }

    ok := True
    Try {
        VarSetCapacity(ctBuf, SSB2_CHUNK_SIZE + SSB2_ABYTES, 0)
        VarSetCapacity(ptBuf, SSB2_CHUNK_SIZE, 0)

        Loop %chunkCount% {
            idx := A_Index - 1

            VarSetCapacity(chunkNonce, SSB2_NONCEBYTES, 0)
            fIn.RawRead(chunkNonce, SSB2_NONCEBYTES)

            VarSetCapacity(clenBuf, 4, 0)
            fIn.RawRead(clenBuf, 4)
            ctLen := NumGet(clenBuf, 0, "UInt")

            If (ctLen > SSB2_CHUNK_SIZE + SSB2_ABYTES || ctLen < SSB2_ABYTES)
                Throw Exception("청크 " . idx . " 길이 값이 손상되었습니다.")

            fIn.RawRead(ctBuf, ctLen)

            isLast := (A_Index = chunkCount) ? 1 : 0

            VarSetCapacity(idxAad, 9, 0)
            NumPut(idx, idxAad, 0, "Int64")
            NumPut(isLast, idxAad, 8, "UChar")

            ptLen := ctLen - SSB2_ABYTES
            ret := DllCall("libsodium\crypto_aead_aes256gcm_decrypt"
                , "Ptr",    &ptBuf
                , "Ptr",    0
                , "Ptr",    0
                , "Ptr",    &ctBuf
                , "UInt64", ctLen
                , "Ptr",    &idxAad
                , "UInt64", 9
                , "Ptr",    &chunkNonce
                , "Ptr",    &fek
                , "Int")

            If (ret != 0)
                Throw Exception("청크 " . idx . " 복호화 실패 (패스워드 오류 또는 손상/변조 가능성).")

            fOut.RawWrite(ptBuf, ptLen)
            _SSB2_ZeroMem(ptBuf, ptLen)
            _SSB2_ZeroMem(ctBuf, ctLen)

            If (progressCb != "" && (Mod(A_Index, 4) = 0 || A_Index = chunkCount)) {
                %progressCb%(A_Index, chunkCount)
                Sleep -1
            }
        }

        fOut.Close()
    } Catch e {
        ok := False
        Try fOut.Close()
    }

    fIn.Close()
    _SSB2_ZeroMem(fek, SSB2_KEYBYTES)

    If (!ok) {
        FileDelete, %tmpPath%
        Return False
    }

    Return _SSB2_AtomicCommit(tmpPath, dstPath)
}

; ── 편의 함수: 암호화 후 원본 삭제 ───────────────────────────────
SSB2_EncryptFileAndDelete(password, srcPath, dstPath := "", hint := "", opslimit := "", memlimit := "", progressCb := "") {
    If (dstPath = "")
        dstPath := srcPath . ".Ssibal"
    If (!SSB2_EncryptFile(password, srcPath, dstPath, hint, opslimit, memlimit, progressCb))
        Return False
    FileDelete, %srcPath%
    Return True
}

; ── 편의 함수: 복호화 후 암호화 파일 삭제 ─────────────────────────
SSB2_DecryptFileAndDelete(password, srcPath, dstPath := "", progressCb := "") {
    If (dstPath = "") {
        If (SubStr(srcPath, -6) = "Ssibal" && SubStr(srcPath, StrLen(srcPath) - 6, 1) = ".")
            dstPath := SubStr(srcPath, 1, StrLen(srcPath) - 7)
        Else
            dstPath := srcPath . "_dec"
    }
    If (!SSB2_DecryptFile(password, srcPath, dstPath, progressCb))
        Return False
    FileDelete, %srcPath%
    Return True
}

; ── 내부: 8바이트 매직 문자열을 정확히 8바이트로 기록 ─────────────
_SSB2_WriteStr8(fOut, str8) {
    VarSetCapacity(buf, 9, 0)   ; StrPut은 null 종료 포함 9바이트가 필요
    StrPut(str8, &buf, 9, "UTF-8")
    fOut.RawWrite(buf, 8)       ; null 바이트는 쓰지 않음
}

; ── 내부: 목적 경로와 같은 폴더에 임시 파일 경로 생성 ─────────────
_SSB2_TempPathFor(dstPath) {
    SplitPath dstPath,, dstDir
    If (dstDir = "")
        dstDir := A_WorkingDir
    Random rnd, 100000, 999999
    Return dstDir . "\~ssb2_" . A_TickCount . "_" . rnd . ".tmp"
}

; ── 내부: 임시 파일 → 목적 경로로 원자적 교체(MoveFileEx) ─────────
_SSB2_AtomicCommit(tmpPath, dstPath) {
    MOVEFILE_REPLACE_EXISTING := 0x1
    MOVEFILE_WRITE_THROUGH    := 0x8
    ret := DllCall("MoveFileEx", "Str", tmpPath, "Str", dstPath
        , "UInt", MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH, "Int")
    If (!ret) {
        FileDelete, %tmpPath%
        Return False
    }
    Return True
}
