#NoTrayIcon
#SingleInstance Off
SplitPath A_ScriptName,,,,A_FileName
IfEqual A_IsCompiled,,Run Compiler\Ahk2Exe.exe /in "%A_ScriptFullPath%" /icon Compiler\ico.ico,,UseErrorLevel
IfEqual A_IsCompiled,,ExitApp
#Requires AutoHotkey v1.1
#Include Argon2id.ahk
#Include AES256GCM.ahk
#Include AES_FileEncryptV2.ahk    ; 봉투 암호화+스트리밍(V2) 전용
#Include PlaySine.ahk
#Include SelectFolderEx.ahk

; ── libsodium.dll을 exe 안에 내장했다가 실행 시 %A_Temp%로 추출 ──────────
; FileInstall은 컴파일된 exe에서는 내장된 리소스를 꺼내고, 스크립트로
; 그냥 실행할 때는 같은 폴더의 libsodium.dll을 그대로 복사합니다.
; ⚠ 파일명은 반드시 "libsodium.dll" 그대로 유지해야 합니다 —
;   DllCall("libsodium\sodium_init") 같은 축약 호출은 "libsodium.dll"이라는
;   이름으로 이미 로드된 모듈을 찾는 방식이라, 경로만 A_Temp로 바뀌고
;   파일명이 바뀌면 안 됩니다.
LibSodiumTemp := A_Temp . "\libsodium.dll"
FileInstall, libsodium.dll, %LibSodiumTemp%

If (!AES_Init(LibSodiumTemp) || !Argon2id_Init(LibSodiumTemp)) {
    MsgBox, 16, 초기화 실패, libsodium.dll을 불러오지 못했습니다.`n(%LibSodiumTemp%)`n`n백신 프로그램이 임시 폴더의 DLL 추출/실행을 막았을 수 있습니다.`n`n해결법: %LibSodiumTemp% 을 삭제하고 다시 실행해보세요.
    ExitApp
}

global _ConsoleAttached := False
global _ConsoleOut      := ""

; ── 커맨드라인 인자 파싱 (/key:value, /flag, --key=value 형태 지원) ────────
; 예) sblenc.exe /silent /pw:1234 /mode:enc /t:4 /m:128 a.txt b.jpg
CliParsed := _ParseCliArgs()

If (CliParsed.params.HasKey("help") || CliParsed.params.HasKey("?")) {
    _PrintUsage()
    AES_Free()
    Argon2id_Free()
    ;FileDelete, %LibSodiumTemp%
    ExitApp, 0
}

If (CliParsed.params.HasKey("silent"))
    _RunSilentCli(CliParsed)   ; 내부에서 처리 후 ExitApp으로 종료 (반환 없음)

INI := A_Temp "\Ssibal_Encrypt.ini"
SelectedRows := []
DlgRowNum := 0
DlgColNum := 0
hDlg := 0
hDlgEdit := 0

; 행별 개별 비밀번호 (키=1-based 행, 값=실제 비밀번호)
RowPasswords := {}

IniRead Radio, %INI%, Setting, Radio, 0
IniRead CB1,   %INI%, Setting, CB1,   1
IniRead CB2,   %INI%, Setting, CB2,   0
IniRead ArgonT, %INI%, Setting, ArgonT, 3
IniRead ArgonM, %INI%, Setting, ArgonM, 64
Argon2id_SetParams(ArgonT + 0, Round(ArgonM * 1048576))

; ── ListView : 파일명 | 힌트 | 비밀번호 | 경로 ─────────────────────────────
;   비밀번호 컬럼 → "✓" 또는 "" 만 표시 (실제값은 RowPasswords에)
;   경로 컬럼 → 보임
Gui Add, ListView, x8 y8 w860 h265 vLV +LV0x1 +Multi, 파일명|힌트|비밀번호|경로
LV_ModifyCol(1, 150)
LV_ModifyCol(2, 150)
LV_ModifyCol(3, 70)
LV_ModifyCol(4, 470)
GuiControlGet, hLV, Hwnd, LV

; WM_NOTIFY(0x4E)로 더블클릭 잡기 — AHK v1에서 ListView 더블클릭의 정석
OnMessage(0x4E,  "WM_NOTIFY")
OnMessage(0x204, "WM_RBUTTONDOWN")

; ── 비밀번호 (공용) ──────────────────────────────────────────────────────────
Gui Add, Text,  x8   y282 w60  h21 +0x200, 비밀번호:
Gui Add, Edit,  x70  y282 w680 h21  vEdit gSave hWndhEdt +Password
Gui Add, Button,  x750  y282 w119 h21 vToggle1 gToggle, 비밀번호 표시
SendMessage 0x1501, 1, "비밀번호 (전체 공용 — 개별 지정은 리스트에서 더블클릭)",, ahk_id %hEdt%

; ── 비밀번호 (공용) ──────────────────────────────────────────────────────────
Gui Add, Text,  x8   y308 w60  h21 +0x200, 비밀번호:
Gui Add, Edit,  x70  y308 w680 h21  vEdit2 gSave hWndhEdt2 +Password
Gui Add, Button,  x750  y308 w119 h21 vToggle2 gToggle, 비밀번호 표시
SendMessage 0x1501, 1, "비밀번호 재확인 (전체 공용 — 개별 지정은 리스트에서 더블클릭)",, ahk_id %hEdt2%

; ── 힌트 (공용, 암호화 모드만) ──────────────────────────────────────────────
Gui Add, Text,  x8   y334 w60  h21 +0x200, 힌트:
Gui Add, Edit,  x70  y334 w800 h21  vEditHint hWndhHint
SendMessage 0x1501, 1, "힌트 (전체 공용 — 개별 지정은 리스트에서 더블클릭)",, ahk_id %hHint%

; ── 모드 / 체크박스 ────────────────────────────────────────────────────────
Gui Add, Radio,    x8  y+6  w70  h23  vR1 gModeChange +Checked, 암호화(&E)
Gui Add, Radio,    x+8      w70  h23  vR2 gModeChange, 복호화(&D)
Gui Add, CheckBox, x+8      w238 h23  vCB1 gSave, 암호화 후 다른 폴더에 저장(&B)
Gui Add, CheckBox, x+8      w140 h23  vCB2 gSave, 창 위 항상 표시(&T)

Gui Add, Button, x-200 y-200 w1 h1 gRunAction +Default, OK

Gui Add, StatusBar,, 알림 : 파일을 드래그 & 드롭.

Menu, SettingsMenu, Add, Argon2 고급 설정(&V)..., ShowAdvanced
Menu, MenuBar, Add, 설정(&S), :SettingsMenu
Gui, Menu, MenuBar

Gui +OwnDialogs -DPIScale
Gui Show, w1316, Ssibal 파일 암호화 툴
Gui +LastFound
hGui := WinExist()
hMainGui := hGui

If (Radio = 1)
    GuiControl,, R2, 1
GuiControl,, CB1, %CB1%
GuiControl,, CB2, %CB2%
GoSub Save

; ── CLI로 넘어온 파일/파라미터를 GUI에 미리 채움 ──────────────────
If (CliParsed.files.MaxIndex() >= 1) {
    cliMode := CliParsed.params.HasKey("mode") ? _ToLower(CliParsed.params["mode"]) : ""
    If (cliMode = "enc") {
        GuiControl,, R1, 1
        GoSub Save
    } Else If (cliMode = "dec") {
        GuiControl,, R2, 1
        GoSub Save
    } Else {
        ; /mode 옵션이 없으면 드래그&드롭과 동일하게 확장자 비율로 자동 판별
        cntSsibal := 0, cntOther := 0
        Loop % CliParsed.files.MaxIndex() {
            SplitPath % CliParsed.files[A_Index],,, _ext
            If (_ext = "Ssibal")
                cntSsibal++
            Else
                cntOther++
        }
        autoMode := (cntSsibal > cntOther) ? 2 : 1
        If (autoMode != (R2 = 1 ? 2 : 1)) {
            GuiControl,, % (autoMode = 1 ? "R1" : "R2"), 1
            GoSub Save
        }
    }
    If (CliParsed.params.HasKey("pw"))
    {
        GuiControl,, Edit, % CliParsed.params["pw"]
        GuiControl,, Edit2, % CliParsed.params["pw"]
    }
    Else If (CliParsed.params.HasKey("password"))
        GuiControl,, Edit, % CliParsed.params["password"]
    If (CliParsed.params.HasKey("hint"))
        GuiControl,, EditHint, % CliParsed.params["hint"]

    Loop % CliParsed.files.MaxIndex() {
        f := CliParsed.files[A_Index]
        If FileExist(f)
            _LV_AddFile(f)
    }
    _UpdateStatus()
}
OnMessage(0x201,"WM_LBUTTONDOWN")
Return

WM_LBUTTONDOWN()
{
  PostMessage,0xA1,2,,,A
}

; ══════════════════════════════════════════════════════════════════════════
; WM_NOTIFY — NM_DBLCLK(-3) 으로 더블클릭 감지
; NMHDR 구조: hwndFrom(Ptr) | idFrom(UPtr) | code(Int)
;   32bit 오프셋: 0, 4, 8  /  64bit 오프셋: 0, 8, 12
; ══════════════════════════════════════════════════════════════════════════
WM_NOTIFY(wParam, lParam, msg, hwnd) {
    global hLV, hMainGui, RowPasswords, DlgRowNum, DlgColNum

    If (hwnd != hMainGui)
        Return

    hwndFrom := NumGet(lParam + 0, 0, "Ptr")
    If (hwndFrom != hLV)
        Return

    codeOffset := (A_PtrSize = 8) ? 16 : 8
    code := NumGet(lParam + 0, codeOffset, "Int")

    If (code != -3)   ; NM_DBLCLK
        Return

    rowNum := _LV_HitTestRow()
    colNum := _LV_HitTestCol()

    If (rowNum < 1 || colNum < 1)
        Return

    Gui Submit, NoHide

    ; ── 힌트 컬럼 (2) ──────────────────────────────────────────────────
    If (colNum = 2) {
        If (R2 = 1) {
            SB_SetText("알림 : 복호화 모드에서는 힌트를 편집할 수 없습니다.", 1)
            Return
        }
        LV_GetText(oldHint, rowNum, 2)
        DlgRowNum := rowNum
        DlgColNum := 2
        _ShowInputDlg("힌트 개별 지정", "행 " rowNum " 의 힌트 (비워두면 공용 힌트 사용)", oldHint, False, CB2)
        Return
    }

    ; ── 비밀번호 컬럼 (3) ──────────────────────────────────────────────
    If (colNum = 3) {
        prevPw   := RowPasswords.HasKey(rowNum) ? RowPasswords[rowNum] : ""
        pwStatus := (prevPw != "") ? "개별 설정됨" : "공용 사용 중"
        pwMsg    := "행 " rowNum " 의 비밀번호(비워두면 공용 비밀번호 사용)  현재: " pwStatus
        DlgRowNum := rowNum
        DlgColNum := 3
        _ShowInputDlg("비밀번호 개별 지정", pwMsg, prevPw, True, CB2)
        Return
    }

    If (colNum = 4) {
        LV_GetText(filePath, rowNum, 4)
        SplitPath, filePath,, fileDir
        If (fileDir != "") {
            Run, explorer "%fileDir%"
            SB_SetText("알림 : 폴더 열기 - " fileDir, 1)
        }
        Return
    }
}

; ══════════════════════════════════════════════════════════════════════════
; 우클릭 — 선택 행 수집
; ══════════════════════════════════════════════════════════════════════════
WM_RBUTTONDOWN(wParam, lParam, msg, hwnd) {
    global hLV, SelectedRows
    If (hwnd != hLV)
        Return
    SelectedRows := []
    idx := -1
    Loop {
        idx := DllCall("SendMessage", "Ptr", hLV
                     , "UInt", 0x100C
                     , "Ptr",  idx
                     , "Ptr",  0x0002
                     , "Ptr")
        If (idx < 0)
            Break
        SelectedRows.Push(idx + 1)
    }
}

; ══════════════════════════════════════════════════════════════════════════
; 모드 변경
; ══════════════════════════════════════════════════════════════════════════
ModeChange:
    LV_Delete()
    SelectedRows := []
    RowPasswords := {}
    Gui Submit, NoHide
    GuiControl % (R1 = 1 ? "Enable" : "Disable"), EditHint
    If (R2 = 1)
        GuiControl,, EditHint,
    _UpdateStatus()
Save:
    Gui Submit, NoHide
    IniWrite %R2%,  %INI%, Setting, Radio
    IniWrite %CB1%, %INI%, Setting, CB1
    IniWrite %CB2%, %INI%, Setting, CB2
    Gui % CB2 ? "+AlwaysOnTop" : "-AlwaysOnTop"
Return
Toggle:
    If(A_GuiControl="Toggle1")
    {
        GuiControl,% (Password1:=!Password1)?"-Password":"+Password",Edit
        GuiControl,,Toggle1,% Password1?"비밀번호 숨김":"비밀번호 표시"
    }
    If(A_GuiControl="Toggle2")
    {
        GuiControl,% (Password2:=!Password2)?"-Password":"+Password",Edit2
        GuiControl,,Toggle2,% Password2?"비밀번호 숨김":"비밀번호 표시"
    }
Return

; ══════════════════════════════════════════════════════════════════════════
; 드래그 앤 드롭
; ══════════════════════════════════════════════════════════════════════════
GuiDropFiles:
    Gui Submit, NoHide

    DroppedFiles := []
    Loop Parse, A_GuiEvent, `n
    {
        fileOrDir := A_LoopField

        ; lnk면 대상 경로로 치환
        resolved := _ResolveLnk(fileOrDir)

        ; 폴더인지 확인 (디렉터리면 건너뛰기)
        If InStr(FileExist(resolved), "D")
            Continue

        DroppedFiles.Push(resolved)
    }

    ; 추가된 파일이 하나도 없으면 종료
    If (DroppedFiles.MaxIndex() = 0) {
        SB_SetText("알림 : 폴더는 추가할 수 없습니다. 파일만 드래그하세요.", 1)
        Return
    }

    cntSsibal := 0, cntOther := 0
    For _i, _f in DroppedFiles {
        SplitPath _f,,, _ext
        If (_ext = "Ssibal")
            cntSsibal++
        Else
            cntOther++
    }

    newMode := (cntSsibal > cntOther) ? 2 : 1

    If (newMode != (R2 = 1 ? 2 : 1)) {
        LV_Delete()
        SelectedRows := []
        RowPasswords := {}
        GuiControl,, % (newMode = 1 ? "R1" : "R2"), 1
        GoSub Save
    }

    skipped := 0
    For _i, _f in DroppedFiles {
        SplitPath _f,,, _ext
        If ((newMode = 1 && _ext = "Ssibal") || (newMode = 2 && _ext != "Ssibal"))
            skipped++
        Else
            _LV_AddFile(_f)
    }
    If (skipped > 0)
        SB_SetText("알림 : 모드 불일치로 " skipped "개 제외됨", 1)
    Else
        _UpdateStatus()
Return

; ──────────────────────────────────────────────
; .lnk 파일이면 대상 경로로 치환, 아니면 원본 그대로 반환
; ──────────────────────────────────────────────
_ResolveLnk(filePath) {
    SplitPath filePath,,, ext
    If (ext != "lnk")
        Return filePath

    FileGetShortcut, %filePath%, target
    If (ErrorLevel || target = "")
        Return filePath  ; 읽기 실패하면 원본 경로 유지

    Return target
}

; ══════════════════════════════════════════════════════════════════════════
; 우클릭 메뉴
; ══════════════════════════════════════════════════════════════════════════
GuiContextMenu:
    If (A_GuiControl != "LV")
        Return

    RowCount := LV_GetCount()
    SelCount  := SelectedRows.MaxIndex()

    If (SelCount > 0) {
        label := (SelCount = 1) ? "선택한 파일 제거(&R)" : "선택한 파일 " SelCount "개 제거(&R)"
        Menu LVMenu, Add, %label%, RemoveSelected
        Menu LVMenu, Add
    }
    If (RowCount > 0) {
        Menu LVMenu, Add, 전체 파일 제거(&A), CancelAllFiles
        Menu LVMenu, Add
    }
    Menu LVMenu, Add, 닫기(&X), GuiClose
    Menu LVMenu, Show
    Menu LVMenu, DeleteAll
Return

RemoveSelected:
    Loop % SelectedRows.MaxIndex() {
        delRow := SelectedRows[SelectedRows.MaxIndex() - A_Index + 1]
        LV_Delete(delRow)
        _RowPasswords_ShiftDelete(delRow)
    }
    SelectedRows := []
    _UpdateStatus()
Return

CancelAllFiles:
    LV_Delete()
    SelectedRows := []
    RowPasswords := {}
    _UpdateStatus()
Return

; ══════════════════════════════════════════════════════════════════════════
; 실행 (Enter)
; ══════════════════════════════════════════════════════════════════════════
RunAction:
    Gui Submit, NoHide
    If (LV_GetCount() = 0) {
        SB_SetText("알림 : 파일을 먼저 드래그&&놓으세요.", 1)
        Return
    }
    If (Edit != Edit2)
    {
        SB_SetText("알림 : 비밀번호가 불일치합니다.", 1)
        Return
    }
    If (Edit = "") {
        allHaveOwn := True
        Loop % LV_GetCount() {
            If (!RowPasswords.HasKey(A_Index)) {
                allHaveOwn := False
                Break
            }
        }
        If (!allHaveOwn) {
            SB_SetText("알림 : 비밀번호를 입력하거나 각 파일에 개별 지정하세요.", 1)
            Return
        }
    }
    GoSub ProcessFiles
Return

ProcessFiles:
    total := LV_GetCount()
    FailedFiles := []

    OutFolder := ""
    If (CB1) {
        OutFolder := SelectFolderEx("", "저장할 폴더를 선택하세요", hGui)
        If (OutFolder = "") {
            SB_SetText("알림 : 취소됨", 1)
            Return
        }
    }

    Loop %total%
    {
        rowIdx  := A_Index
        LV_GetText(FullPath, rowIdx, 4)
        LV_GetText(rowHint,  rowIdx, 2)
        SplitPath FullPath, Name, Dir, Ext, Stem

        ; 비밀번호: 개별 > 공용
        usePw := RowPasswords.HasKey(rowIdx) ? RowPasswords[rowIdx] : Edit
        If (usePw = "") {
            SB_SetText("건너뜀 : 비밀번호 없음 - " Name, 1)
            Continue
        }

        ; 힌트: 개별 컬럼값 > 공용 입력란
        useHint := (rowHint != "") ? rowHint : EditHint

        If (R1 = 1) {
            If (Ext = "Ssibal") {
                SB_SetText("건너뜀 : 이미 암호화된 파일 - " Name, 1)
                Continue
            }
            Dst := CB1 ? OutFolder "\" Name ".Ssibal" : Dir "\" Name ".Ssibal"
            If (Dst = "" || !_OkOverwrite(Dst))
                Continue
            ; 신규 암호화는 전부 V2(봉투 암호화 + 청크 스트리밍) 포맷 사용
            ok := SSB2_EncryptFile(usePw, FullPath, Dst, useHint, "", "", "_ProgressUpdate")
            If (ok)
            {
                PlaySine(440, 130, 160, "Play1_" A_Index, false)
                PlaySine(660, 130, 160, "Play2_" A_Index, true)
            }
            Else
            {
                PlaySine(330, 650, 300, "Play1_1", false)
                PlaySine(660, 130, 160, "Play2_2", true)
            }
            SB_SetText(ok ? "완료 : " Name " 암호화됨" : "실패 : " Name, 1)
        }

        If (R2 = 1) {
            If (Ext != "Ssibal") {
                SB_SetText("건너뜀 : 암호화 파일이 아님 - " Name, 1)
                Continue
            }
            SplitPath Stem,,, Ext2
            Dst := CB1 ? OutFolder "\" Stem : Dir "\" Stem
            If (Dst = "" || !_OkOverwrite(Dst))
                Continue
            ok := SSB2_DecryptFile(usePw, FullPath, Dst, "_ProgressUpdate")
            If (ok) {
                PlaySine(440, 130, 160, "Play1_" A_Index, false)
                PlaySine(660, 130, 160, "Play2_" A_Index, true)
                SB_SetText("완료 : " Stem " 복호화됨", 1)
            } Else {
                PlaySine(330, 650, 300, "Play1_1", false)
                PlaySine(660, 130, 160, "Play2_2", true)
                FailedFiles.Push(Stem)
            }
        }
    }

    LV_Delete()
    SelectedRows := []
    RowPasswords := {}
    _UpdateStatus()

    If (FailedFiles.MaxIndex() > 0) {
        failCount := FailedFiles.MaxIndex()
        msg := failCount " 개 실패 (비밀번호 오류 또는 파일 손상):`n`n"
        For _i, _n in FailedFiles
            msg .= "  - " _n "`n"
        MsgBox % (CB2 ? 262192 : 48), 복호화 실패, %msg%
    }
Return

GuiEscape:
GuiClose:
    AES_Free()
    Argon2id_Free()
    ;FileDelete, %LibSodiumTemp%
    ExitApp

; ══════════════════════════════════════════════════════════════════════════
; 청크 진행률 콜백 (SSB2_EncryptFile / SSB2_DecryptFile 에서 호출)
; ══════════════════════════════════════════════════════════════════════════
_ProgressUpdate(done, total) {
    pct := (total > 0) ? Round(done / total * 100) : 100
    SB_SetText("처리 중... " done "/" total " 청크 (" pct "%)", 1)
}

; ── AHK v1에는 StrLower() 함수가 없음(v2 전용) — StringLower 커맨드로 대체 ──
_ToLower(str) {
    StringLower, out, str
    Return out
}

; ── 상대경로를 현재 작업 폴더(A_WorkingDir) 기준 절대경로로 변환 ─────────
; 커맨드라인에서 "test.txt"처럼 폴더 없이 넘어오면 SplitPath가 Dir을
; 빈 문자열로 돌려주고, 그 상태로 출력 경로를 만들면 드라이브 루트
; (\test.txt.Ssibal)로 잘못 계산되는 문제를 막기 위함.
_ResolveFullPath(path) {
    If (path = "")
        Return path
    ; 이미 절대경로(드라이브 문자 "C:" 또는 UNC "\\...")면 그대로 반환
    If (SubStr(path, 2, 1) = ":" || SubStr(path, 1, 2) = "\\")
        Return path
    workDir := A_WorkingDir
    If (SubStr(workDir, 0) = "\")
        workDir := SubStr(workDir, 1, StrLen(workDir) - 1)
    Return workDir . "\" . path
}

; ══════════════════════════════════════════════════════════════════════════
; 커맨드라인 인자 파싱
;   /key:value , /key=value , --key:value , --key=value , /flag(값 없음)
;   "/" 또는 "--"로 시작하지 않는 인자는 전부 파일 경로로 취급.
;   결과: {files:[...], params:{키(소문자):값}}  (값 없는 flag는 True)
; ══════════════════════════════════════════════════════════════════════════
_ParseCliArgs() {
    files  := []
    params := {}

    For i, arg in A_Args {
        If (SubStr(arg, 1, 2) = "--")
            body := SubStr(arg, 3)
        Else If (SubStr(arg, 1, 1) = "/")
            body := SubStr(arg, 2)
        Else {
            files.Push(arg)
            Continue
        }

        sepPos := InStr(body, ":")
        If (!sepPos)
            sepPos := InStr(body, "=")

        If (sepPos) {
            key := SubStr(body, 1, sepPos - 1)
            val := SubStr(body, sepPos + 1)
        } Else {
            key := body
            val := "true"   ; 값 없는 flag 표시용 센티널 (숫자 "1"과 안 겹치게 문자열로)
        }
        params[_ToLower(key)] := val
    }

    result := {}
    result.files  := files
    result.params := params
    Return result
}

; ── 콘솔(부모 cmd) 출력 — 컴파일된 GUI 서브시스템 exe는 콘솔에 자동으로
;   붙지 않으므로 AttachConsole + CONOUT$ 로 직접 붙여서 씀. 콘솔 없이
;   (탐색기 더블클릭 등으로) 실행됐으면 조용히 아무 것도 하지 않음 ──────
_ConsoleInit() {
    global _ConsoleAttached, _ConsoleOut
    If (_ConsoleAttached)
        Return
    If (DllCall("AttachConsole", "Int", -1)) {
        _ConsoleOut := FileOpen("CONOUT$", "w")
        _ConsoleAttached := IsObject(_ConsoleOut)
    }
}

_ConsoleWrite(text) {
    global _ConsoleAttached, _ConsoleOut
    If (_ConsoleAttached)
        _ConsoleOut.WriteLine(text)
}

; ══════════════════════════════════════════════════════════════════════════
; 사용법 출력 (/help, /?)
; ══════════════════════════════════════════════════════════════════════════
_PrintUsage() {
    global _ConsoleAttached
    usage =
    (
Ssibal 파일 암호화 툴 - 커맨드라인 사용법

  sblenc.exe [옵션] 파일1 [파일2 ...]

옵션:
  /pw:비밀번호        공용 비밀번호 (/silent 모드에서는 필수)
  /hint:힌트          공용 힌트 (암호화 시, 평문 저장됨)
  /mode:enc|dec|auto  처리 모드 (기본값 auto - 확장자/매직헤더로 자동판별)
  /out:폴더           결과 파일을 이 폴더에 저장 (/silent 전용)
  /delete             처리 성공 후 원본 파일 삭제 (/silent 전용)
  /t:숫자             Argon2 시간 비용(opslimit), 이번 실행에만 적용
  /m:숫자             Argon2 메모리 비용 MiB(memlimit), 이번 실행에만 적용
  /silent             GUI 없이 즉시 처리 후 종료 (콘솔에 결과 출력)
  /help, /?           이 도움말 표시

종료 코드(/silent) : 0=전체 성공, 1=입력 오류, 2=일부/전체 실패

예:
  sblenc.exe /silent /pw:1234 /mode:enc a.txt b.jpg
  sblenc.exe /silent /pw:1234 /mode:dec /out:C:\dec a.txt.Ssibal
  sblenc.exe /pw:1234 /hint:메모 a.txt        (GUI에 미리 채워서 열기)
    )
    _ConsoleInit()
    If (_ConsoleAttached)
        _ConsoleWrite(usage)
    Else
        MsgBox, 64, 사용법, %usage%
}

; ══════════════════════════════════════════════════════════════════════════
; /silent 모드 — GUI 없이 즉시 처리하고 종료
; ══════════════════════════════════════════════════════════════════════════
_RunSilentCli(parsed) {
    global LibSodiumTemp

    _ConsoleInit()

    files  := parsed.files
    params := parsed.params

    pw := ""
    If (params.HasKey("pw"))
        pw := params["pw"]
    Else If (params.HasKey("password"))
        pw := params["password"]

    If (pw = "" || pw = "true") {
        _ConsoleWrite("오류 : /silent 모드는 /pw:비밀번호 가 필요합니다.")
        AES_Free()
        Argon2id_Free()
        ;FileDelete, %LibSodiumTemp%
        ExitApp, 1
    }
    If (files.MaxIndex() = 0) {
        _ConsoleWrite("오류 : 처리할 파일이 없습니다.")
        AES_Free()
        Argon2id_Free()
        ;FileDelete, %LibSodiumTemp%
        ExitApp, 1
    }

    hint   := params.HasKey("hint") ? params["hint"] : ""
    mode   := params.HasKey("mode") ? _ToLower(params["mode"]) : "auto"
    outDir := params.HasKey("out")  ? params["out"]  : ""
    doDel  := params.HasKey("delete")

    opslimit := (params.HasKey("t") && params["t"] != "true") ? params["t"] + 0 : ""
    memlimit := (params.HasKey("m") && params["m"] != "true") ? Round(params["m"] * 1048576) : ""

    If (outDir != "" && !InStr(FileExist(outDir), "D"))
        FileCreateDir, %outDir%

    total     := files.MaxIndex()
    failCount := 0

    Loop % total {
        FullPath := _ResolveFullPath(files[A_Index])
        If (!FileExist(FullPath)) {
            _ConsoleWrite("건너뜀 : 파일 없음 - " FullPath)
            failCount++
            Continue
        }
        SplitPath FullPath, Name, Dir, Ext, Stem

        thisMode := mode
        If (thisMode = "auto")
            thisMode := (Ext = "Ssibal") ? "dec" : "enc"

        If (thisMode = "enc") {
            If (Ext = "Ssibal") {
                _ConsoleWrite("건너뜀 : 이미 암호화된 파일 - " Name)
                Continue
            }
            Dst := (outDir != "") ? outDir "\" Name ".Ssibal" : Dir "\" Name ".Ssibal"
            ok := SSB2_EncryptFile(pw, FullPath, Dst, hint, opslimit, memlimit)
            If (ok)
            {
                PlaySine(440, 130, 160, "Play1_" A_Index, false)
                PlaySine(660, 130, 160, "Play2_" A_Index, true)
            }
            Else
            {
                PlaySine(330, 650, 300, "Play1_1", false)
                PlaySine(660, 130, 160, "Play2_2", true)
            }
            _ConsoleWrite((ok ? "완료 : " : "실패 : ") . Name . " -> " . Dst)
            If (!ok)
                failCount++
            Else If (doDel)
                FileDelete, %FullPath%
        } Else If (thisMode = "dec") {
            If (Ext != "Ssibal") {
                _ConsoleWrite("건너뜀 : 암호화 파일이 아님 - " Name)
                Continue
            }
            Dst := (outDir != "") ? outDir "\" Stem : Dir "\" Stem
            ok := SSB2_DecryptFile(pw, FullPath, Dst)
            If (ok)
            {
                PlaySine(440, 130, 160, "Play1_" A_Index, false)
                PlaySine(660, 130, 160, "Play2_" A_Index, true)
            }
            Else
            {
                PlaySine(330, 650, 300, "Play1_1", false)
                PlaySine(660, 130, 160, "Play2_2", true)
            }
            _ConsoleWrite((ok ? "완료 : " : "실패 : ") . Stem . " -> " . Dst)
            If (!ok)
                failCount++
            Else If (doDel)
                FileDelete, %FullPath%
        } Else {
            _ConsoleWrite("오류 : 알 수 없는 모드 - " thisMode)
            failCount++
        }
    }

    _ConsoleWrite("---")
    _ConsoleWrite((total - failCount) . "/" . total . " 성공")

    AES_Free()
    Argon2id_Free()
    ;FileDelete, %LibSodiumTemp%
    ExitApp, % (failCount > 0) ? 2 : 0
}

; ══════════════════════════════════════════════════════════════════════════
; Argon2id 고급 설정 (신규 암호화에 적용될 시간/메모리 비용)
; ══════════════════════════════════════════════════════════════════════════
ShowAdvanced:
    _ShowAdvancedDlg()
Return

_ShowAdvancedDlg() {
    global hMainGui, _Argon2id_OPSLIMIT, _Argon2id_MEMLIMIT

    curT := _Argon2id_OPSLIMIT
    curM := Round(_Argon2id_MEMLIMIT / 1048576)

    Gui New, hWndhAdv, Adv
    Gui % "+Owner" . hMainGui
    Gui +AlwaysOnTop
    Gui Color, White
    Gui Font, s9, Segoe UI
    Gui Margin, 12, 12
    Gui Add, Text,   x12  y12  w300, Argon2id 파라미터 (앞으로 새로 암호화할 파일에 적용됩니다)
    Gui Add, Text,   x12  y+14 w150, 시간 비용(반복 횟수, t):
    Gui Add, Edit,   x170 y+-20 w80 vAdvT, %curT%
    Gui Add, Text,   x12  y+12 w150, 메모리 비용(MiB, m):
    Gui Add, Edit,   x170 y+-20 w80 vAdvM, %curM%
    Gui Add, Text,   x12  y+16 w300 cGray, 기존 파일은 저장된 값을 그대로 다시 읽어 사용하므로 영향받지 않습니다.
    Gui Add, Button, gAdvOK     x120 y+16 w80 h24 Default, &확인
    Gui Add, Button, gAdvCancel x208 y+-24 w80 h24,          &취소
    WinSet Disable,, ahk_id %hMainGui%
    Gui Show, w324, Argon2id 고급 설정
}

AdvOK:
    Gui Submit, NoHide
    If (AdvT < 1 || AdvM < 8) {
        MsgBox, 48, 값 오류, 시간 비용은 1 이상, 메모리 비용은 8MiB 이상이어야 합니다.
        Return
    }
    Argon2id_SetParams(AdvT + 0, Round(AdvM * 1048576))
    IniWrite %AdvT%, %INI%, Setting, ArgonT
    IniWrite %AdvM%, %INI%, Setting, ArgonM
    SB_SetText("알림 : Argon2 파라미터 변경됨 (t=" AdvT ", m=" AdvM "MiB) - 새 암호화부터 적용됨", 1)
    WinSet Enable,, ahk_id %hMainGui%
    Gui Destroy
    Gui 1:Default
    WinActivate ahk_id %hMainGui%
Return

AdvCancel:
AdvGuiClose:
AdvGuiEscape:
    WinSet Enable,, ahk_id %hMainGui%
    Gui Destroy
    Gui 1:Default
    WinActivate ahk_id %hMainGui%
Return

; ── 입력 다이얼로그 OK ───────────────────────────────────────────────────
InputDlgOK:
    VarSetCapacity(dlgVal, 2048)
    SendMessage, 0x000D, 1023, &dlgVal,, ahk_id %hDlgEdit%
    dlgVal := StrGet(&dlgVal)
    WinSet Enable,, ahk_id %hMainGui%
    Gui %hDlg%:Destroy
    hDlg := 0
    Gui 1:Default
    WinActivate ahk_id %hMainGui%
    If (DlgColNum = 2) {
        LV_Modify(DlgRowNum, "", , dlgVal)
        SB_SetText("알림 : 행 " DlgRowNum " 힌트 설정됨.", 1)
    } Else If (DlgColNum = 3) {
        If (dlgVal = "") {
            RowPasswords.Delete(DlgRowNum)
            LV_Modify(DlgRowNum, "", , , "")
            SB_SetText("알림 : 행 " DlgRowNum " 개별 비밀번호 삭제됨 (공용 사용).", 1)
        } Else {
            RowPasswords[DlgRowNum] := dlgVal
            LV_Modify(DlgRowNum, "", , , "✓")
            SB_SetText("알림 : 행 " DlgRowNum " 개별 비밀번호 설정됨.", 1)
        }
    }
Return

InputDlgCancel:
InputDlgEscape:
    WinSet Enable,, ahk_id %hMainGui%
    Gui %hDlg%:Destroy
    hDlg := 0
    Gui 1:Default
    WinActivate ahk_id %hMainGui%
Return

~Delete::
    IfWinActive, ahk_class AutoHotkeyGUI
    {
        ControlGetFocus, _fc, A
        ControlGet, _fchwnd, Hwnd,, %_fc%, A
        If (_fchwnd = hLV)
        {
            SelectedRows := []
            _idx := -1
            Loop {
                _idx := DllCall("SendMessage", "Ptr", hLV
                             , "UInt", 0x100C
                             , "Ptr",  _idx
                             , "Ptr",  0x0002
                             , "Ptr")
                If (_idx < 0)
                    Break
                SelectedRows.Push(_idx + 1)
            }
            GoSub RemoveSelected
        }
    }
Return

; ══════════════════════════════════════════════════════════════════════════
; 내부 함수
; ══════════════════════════════════════════════════════════════════════════

_LV_AddFile(FullPath) {
    SplitPath FullPath, Name

    ; 중복 체크 (4번 컬럼 = 경로)
    Loop % LV_GetCount() {
        LV_GetText(existing, A_Index, 4)
        If (existing = FullPath)
            Return
    }

    ; .Ssibal 이면 힌트 미리 읽기
    hint := ""
    SplitPath FullPath,,, _ext
    If (_ext = "Ssibal")
        hint := SSB2_ReadHint(FullPath)

    ; 파일명 | 힌트 | 비번(✓) | 경로
    LV_Add("", Name, hint, "", FullPath)
}

_RowPasswords_ShiftDelete(delRow) {
    global RowPasswords
    newRP := {}
    For k, v in RowPasswords {
        If (k < delRow)
            newRP[k] := v
        Else If (k > delRow)
            newRP[k - 1] := v
    }
    RowPasswords := newRP
}

; 마우스 위치 → LV 행 번호 (1-based, 없으면 0)
_LV_HitTestRow() {
    global hLV
    VarSetCapacity(pt, 8, 0)
    DllCall("GetCursorPos", "Ptr", &pt)
    DllCall("ScreenToClient", "Ptr", hLV, "Ptr", &pt)
    x := NumGet(pt, 0, "Int")
    y := NumGet(pt, 4, "Int")
    VarSetCapacity(hti, 24, 0)
    NumPut(x, hti, 0, "Int")
    NumPut(y, hti, 4, "Int")
    DllCall("SendMessage", "Ptr", hLV, "UInt", 0x1012, "Ptr", 0, "Ptr", &hti, "Ptr")
    row := NumGet(hti, 12, "Int")
    Return (row >= 0) ? row + 1 : 0
}

; 마우스 위치 → LV 컬럼 번호 (1-based, 없으면 0)
; LVM_SUBITEMHITTEST = 0x1039
_LV_HitTestCol() {
    global hLV
    VarSetCapacity(pt, 8, 0)
    DllCall("GetCursorPos", "Ptr", &pt)
    DllCall("ScreenToClient", "Ptr", hLV, "Ptr", &pt)
    x := NumGet(pt, 0, "Int")
    y := NumGet(pt, 4, "Int")
    VarSetCapacity(hti, 24, 0)
    NumPut(x, hti, 0, "Int")
    NumPut(y, hti, 4, "Int")
    DllCall("SendMessage", "Ptr", hLV, "UInt", 0x1039, "Ptr", 0, "Ptr", &hti, "Ptr")
    col := NumGet(hti, 16, "Int")
    Return (col >= 0) ? col + 1 : 0
}

_UpdateStatus() {
    n := LV_GetCount()
    If (n = 0)
        SB_SetText("알림 : 파일을 드래그 && 놓으세요.", 1)
    Else
        SB_SetText("알림 : 파일 " n "개 로드됨.  Enter로 실행  /  우클릭으로 관리  /  힌트·비번 컬럼 더블클릭으로 개별 지정", 1)
}

_OkOverwrite(Path) {
    global CB2
    If !FileExist(Path)
        Return True
    MsgBox % (CB2 ? 262148 : 4), 덮어쓰기 확인, 파일이 이미 존재합니다. 덮어쓰시겠습니까?
    IfMsgBox No
    {
        SB_SetText("알림 : 취소됨", 1)
        Return False
    }
    Return True
}

_ShowInputDlg(title, prompt, default_, isPassword, alwaysOnTop) {
    global hDlg, hMainGui, hDlgEdit

    Gui New, hWndhDlg LabelInputDlg
    Gui % "+Owner" . hMainGui
    If (alwaysOnTop)
        Gui +AlwaysOnTop
    Gui Color, White
    Gui Font, s9, Segoe UI
    Gui Margin, 12, 12
    Gui Add, Text,   x12 y12 w416, %prompt%
    opts := "hWndhDlgEdit x12 y42 w416 h21"
    If (isPassword)
        opts .= " +Password"
    Gui Add, Edit, %opts%, %default_%
    Gui Add, Button, gInputDlgOK     x260 y74 w80 h24 Default, &확인
    Gui Add, Button, gInputDlgCancel x348 y74 w80 h24,          &취소
    WinSet Disable,, ahk_id %hMainGui%
    Gui Show, w440, %title%

    ; ----- 추가된 부분: 항상 최상위로 만들고 활성화 -----
    WinSet AlwaysOnTop, On, ahk_id %hDlg%
    WinActivate ahk_id %hDlg%
    ; ------------------------------------------------

    If (alwaysOnTop)
        WinSet AlwaysOnTop, On, ahk_id %hDlg%
    ; 중복 적용이지만 안전함. 위에서 이미 항상 On으로 설정했음.
}
