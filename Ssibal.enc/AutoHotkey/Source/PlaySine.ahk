; ============================================================
; PlaySine 함수
;  - 매 호출마다 alias/임시파일을 고유하게 만들어 충돌 방지
;  - 재생이 끝나면 (useSleep=false여도) 자동으로 close + 임시파일 삭제
; ============================================================
global _PlaySineSeq := 0

PlaySine(freq, duration, volume := 50, deviceName := "SineWave", useSleep := true) {
    ; v1에서 가장 안전한 변수 할당 방식
    SR := 44100
    BPS := 16

    nSamples := Round(SR * duration / 1000)
    dataSize := nSamples * (BPS // 8)
    fileSize := 44 + dataSize

    VarSetCapacity(wav, fileSize, 0)

    ; 헤더 작성
    StrPut("RIFF", &wav + 0, 4, "CP0")
    NumPut(fileSize - 8, wav, 4, "UInt")
    StrPut("WAVE", &wav + 8, 4, "CP0")
    StrPut("fmt ", &wav + 12, 4, "CP0")
    NumPut(16, wav, 16, "UInt")
    NumPut(1,  wav, 20, "UShort")
    NumPut(1,  wav, 22, "UShort")
    NumPut(SR, wav, 24, "UInt")
    NumPut(SR * (BPS // 8), wav, 28, "UInt")
    NumPut(BPS // 8, wav, 32, "UShort")
    NumPut(BPS, wav, 34, "UShort")
    StrPut("data", &wav + 36, 4, "CP0")
    NumPut(dataSize, wav, 40, "UInt")

    ; 사인파 데이터 채우기
    PI := 3.141592653589793
    mult := (volume / 100) * 32767
    Loop % nSamples {
        sample := Round(Sin(2 * PI * freq * (A_Index-1) / SR) * mult)
        NumPut(sample, wav, 44 + (A_Index-1)*2, "Short")
    }

    ; --- 호출마다 고유한 alias / 임시파일명 생성 (충돌 방지) ---
    _PlaySineSeq++
    uid      := A_TickCount "_" _PlaySineSeq
    alias    := RegExReplace(deviceName, "[^A-Za-z0-9_]", "_") "_" uid
    tmpFile  := A_Temp "\tmp_sine_" alias ".wav"

    file := FileOpen(tmpFile, "w")
    If (!IsObject(file)) {
        OutputDebug % "PlaySine: 임시 파일 생성 실패 - " tmpFile
        Return false
    }
    file.RawWrite(&wav, fileSize)
    file.Close()

    err := DllCall("winmm\mciSendString", "Str", "open """ tmpFile """ alias " alias, "Ptr", 0, "UInt", 0, "Ptr", 0)
    If (err) {
        OutputDebug % "PlaySine: mci open 실패 (code " err ") - " alias
        FileDelete, %tmpFile%
        Return false
    }

    err := DllCall("winmm\mciSendString", "Str", "play " alias " from 0", "Ptr", 0, "UInt", 0, "Ptr", 0)
    If (err) {
        OutputDebug % "PlaySine: mci play 실패 (code " err ") - " alias
        DllCall("winmm\mciSendString", "Str", "close " alias, "Ptr", 0, "UInt", 0, "Ptr", 0)
        FileDelete, %tmpFile%
        Return false
    }

    ; --- 재생 종료 후 정리(close + 임시파일 삭제) ---
    If (useSleep) {
        CustomSleep(duration)
        _PlaySineCleanup(alias, tmpFile)
    } Else {
        ; 비동기 재생: duration 만큼 뒤에 한 번만 실행되는 타이머로 정리
        cleanupFunc := Func("_PlaySineCleanup").Bind(alias, tmpFile)
        delay := (duration > 50) ? duration : 50
        SetTimer, % cleanupFunc, % -delay
    }

    Return true
}

; ============================================================
; 재생이 끝난 MCI 디바이스를 닫고 임시 wav 파일을 삭제
; ============================================================
_PlaySineCleanup(alias, tmpFile) {
    DllCall("winmm\mciSendString", "Str", "close " alias, "Ptr", 0, "UInt", 0, "Ptr", 0)
    FileDelete, %tmpFile%
}

; ============================================================
; 자체 슬립 (단축키 기능 제외)
; ============================================================
CustomSleep(milliseconds) {
    StartTickCount := A_TickCount
    Loop
    {
        if ((A_TickCount - StartTickCount) >= milliseconds)
            break
        Sleep, 1
    }
}
