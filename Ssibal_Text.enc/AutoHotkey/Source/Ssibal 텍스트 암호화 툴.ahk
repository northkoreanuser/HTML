; ================================================================
; Ssibal 텍스트 암호화 툴 (AutoHotkey판) — libargon2 지원
; 필요: libargon2.dll
; ================================================================

#NoTrayIcon
#SingleInstance Off
#Requires AutoHotkey v1.1
#Include Argon2id.ahk
#Include AES256GCM.ahk

SplitPath A_ScriptName,,,,A_FileName
IfEqual A_IsCompiled,,Run Compiler\Ahk2Exe.exe /in "%A_ScriptFullPath%" /icon Compiler\ico.ico,,UseErrorLevel
IfEqual A_IsCompiled,,ExitApp

If (!AES_Init() || !Argon2id_Init()) {
    ;MsgBox, 16, 초기화 실패, libargon2.dll을 불러오지 못했습니다.`n`n이 스크립트와 같은 폴더에 libargon2.dll이 있는지 확인하세요.
    MsgBox, 16, 초기화 실패, libargon2.dll 혹은 libsodium.dll를 불러오지 못했습니다.
    ExitApp
}

global MARKER := "AGCM1:"

; ---- 상태 ----
global detected         := "empty"
global detectedEnvelope := ""
global savedHint         := ""
global hintIsRO          := false
global pwVisible         := false
global CurPresetM        := 64       ; MiB
global CurPresetT        := 3
global CurPresetP        := 1

; ---- 상한선 ----
global MAX_MEM   := 1024   ; MiB
global MAX_TIME  := 10
global MAX_PARAL := 8

; ---- CPU 코어 수 (자동 감지 - 실행 즉시 측정) ----
global CPU_CORES := 1

; ── CPU 코어 수 감지 ─────────────────────────────────────────────
_GetCpuCores() {
    ; 방법 1: 환경 변수 (Windows) - AHK v1 방식
    cores := ""
    EnvGet, cores, NUMBER_OF_PROCESSORS
    If cores is integer
        Return cores

    ; 방법 2: GetSystemInfo
    VarSetCapacity(sysinfo, 48, 0)
    DllCall("GetSystemInfo", "Ptr", &sysinfo)
    cores := NumGet(sysinfo, 16, "UInt")  ; dwNumberOfProcessors
    If cores > 0
        Return cores

    Return 1
}

; ── 병렬도 자동 계산 ──────────────────────────────────────────────
_GetAutoParallel() {
    global CPU_CORES, MAX_PARAL
    ; CPU 코어 수, 최대 8로 제한
    paral := CPU_CORES
    If (paral > MAX_PARAL)
        paral := MAX_PARAL
    Return paral
}

; ================================================================
; ── 실행 즉시 CPU 코어 측정 및 초기값 설정 ──────────────────────
; ================================================================
CPU_CORES := _GetCpuCores()
CurPresetP := _GetAutoParallel()  ; 초기 병렬도를 자동으로 설정

; ================================================================
; ── GUI 구성 ──────────────────────────────────────────────────────
; ================================================================
Gui, Font, s10, Segoe UI
Gui, Margin, 12, 12

Gui, Font, s10 Bold, Segoe UI
Gui, Add, Text, x12 y12 w816 h20 vModeText c0x1a5276, ? 입력을 기다리는 중
Gui, Font, s10, Segoe UI

; 초기값: 파라미터 파일 or 클립보드
initialText := ""
If (A_Args.Length() > 0) {
    filePath := A_Args[1]
    If (FileExist(filePath)) {
        file := FileOpen(filePath, "r", "UTF-8-RAW")
        If (IsObject(file)) {
            initialText := file.Read()
            file.Close()
        }
    }
}
If (initialText = "" && A_Args.Length() = 0) {
    initialText := A_Clipboard
}

Gui, Add, Edit, x12 y+8 w816 r14 vInputText gInputChanged +WantReturn, %initialText%
Gui, Add, Text, x12 y+2 w816 h16 vCharCountText Right c0x808080,

Gui, Add, Text, x12 y+8 w90 h21 +0x200, 보안 강도:
Gui, Add, DropDownList, x110 y+-21 w320 vPresetCombo gPresetChanged
    , 인터랙티브 (32 MiB · 2회)|보통 (64 MiB · 3회)|민감 (256 MiB · 4회)|편집증 (1024 MiB · 6회)|사용자 지정...
GuiControl, Choose, PresetCombo, 2

Gui, Add, Text, x12 y+10 w90 h21 +0x200, 힌트:
Gui, Add, Edit, x110 y+-21 w718 vHintInput

Gui, Add, Text, x12 y+10 w90 h21 +0x200, 비밀번호:
Gui, Add, Edit, x110 y+-21 w600 vPasswordInput +Password
Gui, Add, Button, x+8 w110 h21 vToggleBtn gTogglePw, 보기

Gui, Add, Text, x12 y+10 w90 h21 +0x200, 비밀번호:
Gui, Add, Edit, x110 y+-21 w600 vPasswordInput2 +Password
Gui, Add, Button, x+8 w110 h21 vToggleBtn2 gTogglePw, 보기

Gui, Add, Button, x12 y+16 w200 h34 vRunBtn gRunAction Default, 암호화 실행
Gui, Add, Text, x224 y+-30 w604 h34 vStatusText +0x200 c0x444444,

Gui, +OwnDialogs
Gui, Show, w840, Ssibal 텍스트 암호화 툴 (libargon2)
Gui, +LastFound
hMainGui := WinExist()

; 초기 분류 실행
SetTimer, InitClassification, -100
Return

InitClassification:
    UpdateClassification()
Return

; ================================================================
; ── 실시간 분류 ──────────────────────────────────────────────────
; ================================================================
UpdateClassification() {
    global detected, detectedEnvelope, MARKER, savedHint, hintIsRO
    GuiControlGet, raw, , InputText

    trimmed := Trim(raw)

    if (trimmed = "") {
        detected := "empty"
        detectedEnvelope := ""
        GuiControl,, ModeText, ? 입력을 기다리는 중 — 평문을 입력하면 암호화, 암호문(AGCM1:)을 붙여넣으면 자동으로 복호화됩니다.
        GuiControl,, CharCountText,
        GuiControl,, RunBtn, 암호화 실행
        GuiControl, Enable, PresetCombo
        SetHintMode("encrypt")
        Return
    }

    ; 글자수 표시
    GuiControl,, CharCountText, % StrLen(raw) . "자"

    if (SubStr(trimmed, 1, StrLen(MARKER)) = MARKER) {
        parsed := ParseEnvelope(raw)
        if (parsed = "malformed") {
            detected := "invalid"
            detectedEnvelope := ""
            GuiControl,, ModeText, ⚠️ 손상된 암호문 — 스마트 마커는 인식했지만 데이터 형식이 손상되었습니다.
            GuiControl,, RunBtn, 복호화 실행
            GuiControl, Enable, PresetCombo
            SetHintMode("encrypt")
            Return
        } else {
            detected := "decrypt"
            detectedEnvelope := parsed
            mib := Round(parsed.m / 1024)
            if (mib < 1)
                mib := 1
            GuiControl,, ModeText, % "🔒 암호문 감지됨 — 복호화됩니다 · " mib " MiB · " parsed.t " iter · " parsed.p " lane(s)"
            GuiControl,, RunBtn, 복호화 실행
            GuiControl, Disable, PresetCombo
            SetHintMode("decrypt", parsed.hint)
            Return
        }
    } else {
        detected := "encrypt"
        detectedEnvelope := ""
        GuiControl,, ModeText, ✏️ 평문 감지됨 — 암호화됩니다.
        GuiControl,, RunBtn, 암호화 실행
        GuiControl, Enable, PresetCombo
        SetHintMode("encrypt")
        Return
    }
}

InputChanged:
    UpdateClassification()
Return

; ── 힌트 입력창 모드 전환 ──────────────────────────────────────────
SetHintMode(kind, hintVal := "") {
    global savedHint, hintIsRO
    if (kind = "encrypt") {
        if (hintIsRO) {
            GuiControl,, HintInput, %savedHint%
        }
        GuiControl, -ReadOnly, HintInput
        hintIsRO := false
    } else {
        if (!hintIsRO) {
            GuiControlGet, savedHint, , HintInput
        }
        disp := (hintVal != "") ? hintVal : "(이 envelope에는 힌트가 없습니다)"
        GuiControl,, HintInput, %disp%
        GuiControl, +ReadOnly, HintInput
        hintIsRO := true
    }
}

; ================================================================
; ── 프리셋 ────────────────────────────────────────────────────────
; ================================================================
PresetChanged:
    DoPresetChanged()
Return

DoPresetChanged() {
    global CurPresetM, CurPresetT, CurPresetP
    global CPU_CORES

    GuiControlGet, PresetCombo

    ; 병렬도 자동 계산 (프리셋 선택 시 항상 자동)
    autoP := _GetAutoParallel()

    if (PresetCombo = "사용자 지정...") {
        _ShowAdvancedDlg()
    } else if (PresetCombo = "인터랙티브 (32 MiB · 2회)") {
        CurPresetM := 32, CurPresetT := 2, CurPresetP := autoP
    } else if (PresetCombo = "보통 (64 MiB · 3회)") {
        CurPresetM := 64, CurPresetT := 3, CurPresetP := autoP
    } else if (PresetCombo = "민감 (256 MiB · 4회)") {
        CurPresetM := 256, CurPresetT := 4, CurPresetP := autoP
    } else if (PresetCombo = "편집증 (1024 MiB · 6회)") {
        CurPresetM := 1024, CurPresetT := 6, CurPresetP := autoP
    }
}

; ================================================================
; ── 고급 설정 대화상자 ─────────────────────────────────────────────
; ================================================================
_ShowAdvancedDlg() {
    global hMainGui, CurPresetM, CurPresetT, CurPresetP
    global MAX_MEM, MAX_TIME, MAX_PARAL, CPU_CORES

    ; 고급 설정을 열 때 현재 CurPresetP가 기본값(1)이면 자동 병렬도로 갱신
    ; (사용자가 아직 프리셋을 선택하지 않은 상태)
    If (CurPresetP = 1) {
        CurPresetP := _GetAutoParallel()
    }

    curT := CurPresetT
    curM := CurPresetM
    curP := CurPresetP

    Gui, 2:New
    Gui, 2:+AlwaysOnTop
    Gui, 2:Color, White
    Gui, 2:Font, s9, Segoe UI
    Gui, 2:Margin, 12, 12

    ; 제목
    Gui, 2:Add, Text,   x12  y12  w300, Argon2id 파라미터 (libargon2)
    Gui, 2:Add, Text,   x12  y+4  w300 cGray, 상한선: 메모리 1024 MiB · 시간 10 · 병렬도 8 (코어: %CPU_CORES%)

    ; 프리셋 버튼
    Gui, 2:Add, Button, x12 y+10 w70 h23 gAdvPreset1, 인터랙티브
    Gui, 2:Add, Button, x+4 w70 h23 gAdvPreset2, 보통
    Gui, 2:Add, Button, x+4 w70 h23 gAdvPreset3, 민감
    Gui, 2:Add, Button, x+4 w70 h23 gAdvPreset4, 편집증

    ; 입력 필드
    Gui, 2:Add, Text,   x12  y+10 w150, 시간 비용(반복 횟수, t):
    Gui, 2:Add, Edit,   x170 y+-20 w80 vAdvT gAdvValidateT, %curT%
    Gui, 2:Add, Text,   x260 y+-20 w40 cGray, (1~10)

    Gui, 2:Add, Text,   x12  y+10 w150, 메모리 비용(MiB, m):
    Gui, 2:Add, Edit,   x170 y+-20 w80 vAdvM gAdvValidateM, %curM%
    Gui, 2:Add, Text,   x260 y+-20 w40 cGray, (8~1024)

    Gui, 2:Add, Text,   x12  y+10 w150, 병렬도(lanes, p):
    Gui, 2:Add, Edit,   x170 y+-20 w80 vAdvP gAdvValidateP, %curP%
    Gui, 2:Add, Text,   x260 y+-20 w40 cGray, (1~8)

    ; 자동 병렬도 버튼 (CPU 코어 수 표시)
    Gui, 2:Add, Button, x170 y+4 w80 h23 gAdvAutoP, 자동 설정

    ; 버튼
    Gui, 2:Add, Button, gAdvOK     x120 y+16 w80 h24 Default, &확인
    Gui, 2:Add, Button, gAdvCancel x208 y+-24 w80 h24,          &취소

    WinSet, Disable,, ahk_id %hMainGui%
    Gui, 2:Show, w340, Argon2id 고급 설정
}

; ── 고급 설정 프리셋 ──────────────────────────────────────────────
AdvPreset1:
    GuiControl, 2:, AdvT, 2
    GuiControl, 2:, AdvM, 32
    GuiControl, 2:, AdvP, % _GetAutoParallel()
Return

AdvPreset2:
    GuiControl, 2:, AdvT, 3
    GuiControl, 2:, AdvM, 64
    GuiControl, 2:, AdvP, % _GetAutoParallel()
Return

AdvPreset3:
    GuiControl, 2:, AdvT, 4
    GuiControl, 2:, AdvM, 256
    GuiControl, 2:, AdvP, % _GetAutoParallel()
Return

AdvPreset4:
    GuiControl, 2:, AdvT, 6
    GuiControl, 2:, AdvM, 1024
    GuiControl, 2:, AdvP, % _GetAutoParallel()
Return

; ── 자동 병렬도 버튼 ──────────────────────────────────────────────
AdvAutoP:
    autoP := _GetAutoParallel()
    GuiControl, 2:, AdvP, %autoP%
Return

; ── 실시간 검증 (입력 즉시 자동 수정) ─────────────────────────────
AdvValidateT:
    GuiControlGet, val, 2:, AdvT
    If (val = "")
        Return
    If (val < 1) {
        GuiControl, 2:, AdvT, 1
    } Else If (val > MAX_TIME) {
        GuiControl, 2:, AdvT, %MAX_TIME%
    }
Return

AdvValidateM:
    GuiControlGet, val, 2:, AdvM
    If (val = "")
        Return
    If (val < 8) {
        GuiControl, 2:, AdvM, 8
    } Else If (val > MAX_MEM) {
        GuiControl, 2:, AdvM, %MAX_MEM%
    }
Return

AdvValidateP:
    GuiControlGet, val, 2:, AdvP
    If (val = "")
        Return
    If (val < 1) {
        GuiControl, 2:, AdvP, 1
    } Else If (val > MAX_PARAL) {
        GuiControl, 2:, AdvP, %MAX_PARAL%
    }
Return

; ── 고급 설정 확인 ────────────────────────────────────────────────
AdvOK:
    global CurPresetM, CurPresetT, CurPresetP

    Gui, 2:Submit, NoHide

    CurPresetT := AdvT + 0
    CurPresetM := AdvM + 0
    CurPresetP := AdvP + 0

    ; 메인 GUI 프리셋 콤보를 "사용자 지정"으로 변경
    GuiControl, 1:, PresetCombo, 사용자 지정...

    WinSet, Enable,, ahk_id %hMainGui%
    Gui, 2:Destroy
    Gui, 1:Default
    WinActivate, ahk_id %hMainGui%
Return

AdvCancel:
2GuiClose:
2GuiEscape:
    WinSet, Enable,, ahk_id %hMainGui%
    Gui, 2:Destroy
    Gui, 1:Default
    WinActivate, ahk_id %hMainGui%
Return

; ================================================================
; ── 비밀번호 표시/숨기기 ────────────────────────────────────────────
; ================================================================
TogglePw:
    pwVisible := !pwVisible
    GuiControl, % (pwVisible ? "-Password" : "+Password"), PasswordInput
    GuiControl, % (pwVisible ? "-Password" : "+Password"), PasswordInput2
    GuiControl,, ToggleBtn, % (pwVisible ? "숨기기" : "보기")
    GuiControl,, ToggleBtn2, % (pwVisible ? "숨기기" : "보기")
Return

; ================================================================
; ── 실행 버튼 ────────────────────────────────────────────────────
; ================================================================
RunAction:
    GuiControlGet, InputText,, InputText
    GuiControlGet, PasswordInput,, PasswordInput
    GuiControlGet, PasswordInput2,, PasswordInput2

    ; 암호화 모드일 때만 비밀번호 확인
    if (detected = "encrypt") {
        if (PasswordInput != PasswordInput2) {
            GuiControl,, StatusText, ⚠ 비밀번호가 일치하지 않습니다.
            Return
        }
        if (PasswordInput = "") {
            GuiControl,, StatusText, ⚠ 비밀번호를 입력하세요.
            Return
        }
        EncryptFlow(InputText, PasswordInput)
    }
    else if (detected = "decrypt") {
        if (PasswordInput = "") {
            GuiControl,, StatusText, ⚠ 비밀번호를 입력하세요.
            Return
        }
        DecryptFlow(InputText, PasswordInput)
    }
    else if (detected = "invalid") {
        GuiControl,, StatusText, ⚠ 손상된 암호문입니다. 전체 내용을 다시 확인하세요.
    }
    else {
        GuiControl,, StatusText, ⚠ 입력이 비어 있습니다.
    }
Return

; ── 암호화 ───────────────────────────────────────────────────────
EncryptFlow(plaintext, password) {
    global MARKER, CurPresetM, CurPresetT, CurPresetP

    if (password = "") {
        GuiControl,, StatusText, ⚠ 비밀번호를 입력하세요.
        Return
    }
    if (Trim(plaintext) = "") {
        GuiControl,, StatusText, ⚠ 암호화할 메시지를 입력하세요.
        Return
    }

    memMib   := CurPresetM
    timeCost := CurPresetT
    par      := CurPresetP
    memKib   := memMib * 1024

    GuiControl, Disable, RunBtn
    GuiControl,, StatusText, % "⏳ argon2id 파생 중... (" memMib " MiB, " timeCost " iter, " par " lanes)"

    outSalt := ""
    key := Argon2id_DeriveKey(password, outSalt, "", timeCost, memMib, par)
    if (key = "") {
        GuiControl,, StatusText, ❌ 키 파생 실패 (메모리가 부족할 수 있습니다).
        GuiControl, Enable, RunBtn
        Return
    }
    VarSetCapacity(keyBuf, 32, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", 32)

    VarSetCapacity(ivBuf, 12, 0)
    DllCall("advapi32\CryptGenRandom", "Ptr", 0, "UPtr", 12, "Ptr", &ivBuf)

    ptLen := 0
    ptBuf := _UTF8Encode(plaintext, ptLen)

    ctLen := ptLen + 16
    VarSetCapacity(ctBuf, ctLen, 0)

    ret := DllCall("libsodium\crypto_aead_aes256gcm_encrypt"
        , "Ptr",    &ctBuf
        , "Ptr",    0
        , "Ptr",    &ptBuf
        , "UInt64", ptLen
        , "Ptr",    0
        , "UInt64", 0
        , "Ptr",    0
        , "Ptr",    &ivBuf
        , "Ptr",    &keyBuf
        , "Int")

    _ZeroMem(keyBuf, 32)
    _ZeroMem(ptBuf, ptLen)

    if (ret != 0) {
        GuiControl,, StatusText, ❌ 암호화 실패.
        GuiControl, Enable, RunBtn
        Return
    }

    saltB64 := _B64Encode(outSalt, 16)
    ivB64   := _B64Encode(ivBuf, 12)
    ctB64   := _B64Encode(ctBuf, ctLen)

    GuiControlGet, hintVal, , HintInput

    json := BuildEnvelopeJson(memKib, timeCost, par, saltB64, ivB64, ctB64, hintVal)
    jLen := 0
    jBuf := _UTF8Encode(json, jLen)
    envB64 := _B64Encode(jBuf, jLen)
    out := MARKER . envB64

    GuiControl, Enable, RunBtn
    Clipboard := out

    ; 암호화 결과를 입력창에 표시 (자동 복호화 모드로 전환)
    GuiControl,, InputText, %out%
    UpdateClassification()

    FormatTime, ts,, yyyyMMdd-HHmm
    defaultName := "encrypted-" . ts . ".SsibalText"
    FileSelectFile, savePath, 16, %defaultName%, 암호화된 텍스트 저장, SsibalText 파일 (*.SsibalText)

    if (savePath = "") {
        GuiControl,, StatusText, ✅ 암호화 완료 — 저장은 취소되었지만 결과가 클립보드에 복사되었습니다.
        Return
    }
    if !RegExMatch(savePath, "i)\.SsibalText$")
        savePath .= ".SsibalText"

    file := FileOpen(savePath, "w", "UTF-8-RAW")
    if (!IsObject(file)) {
        GuiControl,, StatusText, % "❌ 파일 저장 실패: " savePath " (클립보드에는 복사되었습니다)"
        Return
    }
    file.Write(out)
    file.Close()

    GuiControl,, StatusText, % "✅ 저장 완료: " savePath " (클립보드에도 복사됨)"
}

; ── 복호화 ───────────────────────────────────────────────────────
DecryptFlow(encryptedText, password) {
    global detectedEnvelope

    if (password = "") {
        GuiControl,, StatusText, ⚠ 비밀번호를 입력하세요.
        Return
    }
    env := detectedEnvelope
    if (!IsObject(env)) {
        GuiControl,, StatusText, ⚠ 유효한 암호문이 감지되지 않았습니다.
        Return
    }

    GuiControl, Disable, RunBtn
    mib := Round(env.m / 1024)
    GuiControl,, StatusText, % "⏳ argon2id 파생 중... (" mib " MiB, " env.t " iter, " env.p " lanes)"

    saltLen := 0
    saltBuf := _B64Decode(env.salt, saltLen)
    if (saltLen != 16) {
        GuiControl,, StatusText, ❌ salt 데이터가 손상되었습니다.
        GuiControl, Enable, RunBtn
        Return
    }

    ivLen := 0
    ivBuf := _B64Decode(env.iv, ivLen)
    ctLen := 0
    ctBuf := _B64Decode(env.ct, ctLen)
    if (ivLen != 12 || ctLen < 16) {
        GuiControl,, StatusText, ❌ 암호문 데이터가 손상되었습니다.
        GuiControl, Enable, RunBtn
        Return
    }

    outSalt := ""
    key := Argon2id_DeriveKey(password, outSalt, saltBuf, env.t, mib, env.p)
    if (key = "") {
        GuiControl,, StatusText, ❌ 키 파생 실패 (메모리가 부족할 수 있습니다).
        GuiControl, Enable, RunBtn
        Return
    }
    VarSetCapacity(keyBuf, 32, 0)
    DllCall("RtlMoveMemory", "Ptr", &keyBuf, "Ptr", &key, "UPtr", 32)

    ptLen := ctLen - 16
    VarSetCapacity(ptBuf, ptLen + 1, 0)

    ret := DllCall("libsodium\crypto_aead_aes256gcm_decrypt"
        , "Ptr",    &ptBuf
        , "Ptr",    0
        , "Ptr",    0
        , "Ptr",    &ctBuf
        , "UInt64", ctLen
        , "Ptr",    0
        , "UInt64", 0
        , "Ptr",    &ivBuf
        , "Ptr",    &keyBuf
        , "Int")

    _ZeroMem(keyBuf, 32)
    GuiControl, Enable, RunBtn

    if (ret != 0) {
        _ZeroMem(ptBuf, ptLen)
        GuiControl,, StatusText, ❌ 복호화 실패: 비밀번호가 틀렸거나 데이터가 손상되었습니다 (인증 태그 불일치).
        Return
    }

    plaintext := StrGet(&ptBuf, ptLen, "UTF-8")
    _ZeroMem(ptBuf, ptLen)

    Clipboard := plaintext
    GuiControl,, InputText, %plaintext%
    UpdateClassification()
    GuiControl,, StatusText, ✅ 복호화 성공 — 평문을 입력창과 클립보드에 넣었습니다.
}

; ================================================================
; ── envelope JSON 빌드/파싱 ─────────────────────────────────────
; ================================================================
BuildEnvelopeJson(memKib, timeCost, par, saltB64, ivB64, ctB64, hint) {
    json := "{""v"":1,""kdf"":""argon2id"",""alg"":""AES-256-GCM"",""m"":" memKib ",""t"":" timeCost ",""p"":" par
        . ",""salt"":""" saltB64 """,""iv"":""" ivB64 """,""ct"":""" ctB64 """"
    if (hint != "")
        json .= ",""hint"":""" _JsonEscape(hint) """"
    json .= "}"
    Return json
}

ParseEnvelope(raw) {
    global MARKER
    trimmed := Trim(raw)
    b64 := Trim(SubStr(trimmed, StrLen(MARKER) + 1))
    if (b64 = "")
        Return "malformed"

    len := 0
    bin := _B64Decode(b64, len)
    if (len <= 0)
        Return "malformed"

    jsonStr := StrGet(&bin, len, "UTF-8")
    if (jsonStr = "")
        Return "malformed"

    if (!RegExMatch(jsonStr, """kdf""\s*:\s*""argon2id"""))
        Return "malformed"
    if (!RegExMatch(jsonStr, """alg""\s*:\s*""AES-256-GCM"""))
        Return "malformed"
    if (!RegExMatch(jsonStr, """m""\s*:\s*(\d+)", mOut))
        Return "malformed"
    if (!RegExMatch(jsonStr, """t""\s*:\s*(\d+)", tOut))
        Return "malformed"
    if (!RegExMatch(jsonStr, """p""\s*:\s*(\d+)", pOut))
        Return "malformed"
    if (!RegExMatch(jsonStr, """salt""\s*:\s*""([^""]*)""", saltOut))
        Return "malformed"
    if (!RegExMatch(jsonStr, """iv""\s*:\s*""([^""]*)""", ivOut))
        Return "malformed"
    if (!RegExMatch(jsonStr, """ct""\s*:\s*""([^""]*)""", ctOut))
        Return "malformed"

    if (saltOut1 = "" || ivOut1 = "" || ctOut1 = "")
        Return "malformed"

    hintVal := ""
    if (RegExMatch(jsonStr, """hint""\s*:\s*""((?:[^""\\]|\\.)*)""", hintOut))
        hintVal := _JsonUnescape(hintOut1)

    obj := {}
    obj.m    := mOut1 + 0
    obj.t    := tOut1 + 0
    obj.p    := pOut1 + 0
    obj.salt := saltOut1
    obj.iv   := ivOut1
    obj.ct   := ctOut1
    obj.hint := hintVal
    Return obj
}

_JsonEscape(str) {
    str := StrReplace(str, "\", "\\")
    str := StrReplace(str, """", "\""")
    str := StrReplace(str, "`n", "\n")
    str := StrReplace(str, "`r", "\r")
    str := StrReplace(str, "`t", "\t")
    Return str
}

_JsonUnescape(str) {
    out := ""
    i := 1
    L := StrLen(str)
    While (i <= L) {
        c := SubStr(str, i, 1)
        if (c = "\") {
            nc := SubStr(str, i + 1, 1)
            if (nc = "n") {
                out .= "`n", i += 2
            } else if (nc = "r") {
                out .= "`r", i += 2
            } else if (nc = "t") {
                out .= "`t", i += 2
            } else if (nc = "u") {
                hex := SubStr(str, i + 2, 4)
                out .= Chr(("0x" . hex) + 0)
                i += 6
            } else {
                out .= nc, i += 2
            }
        } else {
            out .= c
            i += 1
        }
    }
    Return out
}

; ================================================================
; ── base64 / UTF-8 헬퍼 ────────────────────────────────────────
; ================================================================
_B64Encode(ByRef bin, len) {
    outLen := 0
    DllCall("crypt32\CryptBinaryToStringW", "Ptr", &bin, "UInt", len, "UInt", 0x40000001, "Ptr", 0, "UInt*", outLen)
    VarSetCapacity(buf, (outLen + 1) * 2, 0)
    DllCall("crypt32\CryptBinaryToStringW", "Ptr", &bin, "UInt", len, "UInt", 0x40000001, "Str", buf, "UInt*", outLen)
    Return buf
}

_B64Decode(str, ByRef outLen) {
    cb := 0
    DllCall("crypt32\CryptStringToBinaryW", "Str", str, "UInt", 0, "UInt", 0x1, "Ptr", 0, "UInt*", cb, "Ptr", 0, "Ptr", 0)
    if (cb = 0) {
        outLen := 0
        Return ""
    }
    VarSetCapacity(buf, cb, 0)
    DllCall("crypt32\CryptStringToBinaryW", "Str", str, "UInt", 0, "UInt", 0x1, "Ptr", &buf, "UInt*", cb, "Ptr", 0, "Ptr", 0)
    outLen := cb
    Return buf
}

_UTF8Encode(str, ByRef outLen) {
    byteLenWithNull := StrPut(str, "UTF-8")
    VarSetCapacity(buf, byteLenWithNull, 0)
    StrPut(str, &buf, byteLenWithNull, "UTF-8")
    outLen := byteLenWithNull - 1
    Return buf
}

_ZeroMem(ByRef buf, size) {
    If (size > 0)
        DllCall("RtlFillMemory", "Ptr", &buf, "UPtr", size, "UChar", 0)
}

; ================================================================
; ── 종료 ────────────────────────────────────────────────────────
; ================================================================
GuiClose:
GuiEscape:
    AES_Free()
    Argon2id_Free()
    ExitApp
Return