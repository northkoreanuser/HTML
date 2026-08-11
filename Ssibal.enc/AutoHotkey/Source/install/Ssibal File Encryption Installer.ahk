#NoTrayIcon
#SingleInstance Force
IfEqual A_IsCompiled,,Run Compiler\Ahk2Exe.exe /in "%A_ScriptFullPath%" /icon Compiler\ico.ico,,UseErrorLevel
IfEqual A_IsCompiled,,ExitApp
IfEqual A_IsAdmin,0,Run *RunAs "%A_ScriptFullPath%" "%파라미터%",,UseErrorLevel
IfEqual A_IsAdmin,0,ExitApp
FileCreateDir % SystemDrive "\mickey90427\sblenc"
FileInstall qr_sheet_1786170982365.html.Ssibal,% SystemDrive "\mickey90427\sblenc\qr_sheet_1786170982365.html.Ssibal",1
FileInstall sblenc.exe,% SystemDrive "\mickey90427\sblenc\sblenc.exe",1
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc,Icon,`%SystemDrive`%\mickey90427\sblenc\sblenc.exe
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc,MUIVerb,Ssibal File Encryption (&S)
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc,Position,Top
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc,SubCommands
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell,enc
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell\enc,Icon,`%SystemDrive`%\mickey90427\sblenc\sblenc.exe
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell\enc,MUIVerb,Ssibal 으로 열기 (&S)
RegWrite REG_EXPAND_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell\enc\command,,"`%SystemDrive`%\mickey90427\sblenc\sblenc" "`%1"
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell\enc_auto,Icon,`%SystemDrive`%\mickey90427\sblenc\sblenc.exe
RegWrite REG_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell\enc_auto,MUIVerb,자동 암호화 (&A)
RegWrite REG_EXPAND_SZ,HKEY_CLASSES_ROOT\*\shell\sblenc\shell\enc_auto\command,,"`%SystemDrive`%\mickey90427\sblenc\sblenc" /silent /pw:SKU-X2JRE7D0TB /hint:"Row: 82 Col: 4 (490)" /mode:enc /t:6 /m:256 "`%1"
