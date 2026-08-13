#NoTrayIcon
#SingleInstance Force
IfEqual A_IsCompiled,,Run Compiler\Ahk2Exe.exe /in "%A_ScriptFullPath%" /icon Compiler\ico.ico,,UseErrorLevel
IfEqual A_IsCompiled,,ExitApp
IfEqual A_IsAdmin,0,Run *RunAs "%A_ScriptFullPath%" "%파라미터%",,UseErrorLevel
IfEqual A_IsAdmin,0,ExitApp
FileCreateDir % SystemDrive "\mickey90427\sbltenc"
FileInstall libargon2.dll,% SystemDrive "\mickey90427\sbltenc\libargon2.dll",1
FileInstall libsodium.dll,% SystemDrive "\mickey90427\sbltenc\libsodium.dll",1
FileInstall qr_sheet_1786170982365.html.Ssibal,% SystemDrive "\mickey90427\sbltenc\qr_sheet_1786170982365.html.Ssibal",1
FileInstall sbltenc.exe,% SystemDrive "\mickey90427\sbltenc\sbltenc.exe",1
RegWrite REG_SZ,HKEY_CLASSES_ROOT\Directory\Background\shell\sbltenc,Icon,`%SystemDrive`%\mickey90427\sblfenc\sblfenc.exe
RegWrite REG_SZ,HKEY_CLASSES_ROOT\Directory\Background\shell\sbltenc,MUIVerb,Ssibal Text Encryption (&S)
RegWrite REG_SZ,HKEY_CLASSES_ROOT\Directory\Background\shell\sbltenc,Position,Top
RegWrite REG_EXPAND_SZ,HKEY_CLASSES_ROOT\Directory\Background\shell\sbltenc\command,,"`%SystemDrive`%\mickey90427\sbltenc\sbltenc"
