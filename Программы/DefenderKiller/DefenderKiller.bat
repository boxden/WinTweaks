:: DefenderKiller by Vlado - 㤠����� � ����⠭������� Windows Defender [���⭨�� Windows]
:: �� ������, ���� � ������ ��㣮� ᯠᨡ� ����� ���� Eject - https://win10tweaker.ru/forum/profile/eject
:: https://win10tweaker.ru/forum/topic/defenderkiller | https://github.com/oatmealcookiec/DefenderKiller

:: Unlocker by Eject - https://win10tweaker.ru/forum/topic/unlocker
:: StopDefender - https://github.com/lab52io/StopDefender [Not Updated...]
:: NSudo - https://github.com/M2TeamArchived/NSudo/releases
:: nhmb - https://nhutils.ru/blog/nhmb/
:: LGPO - https://www.microsoft.com/en-us/download/details.aspx?id=55319
:: Compressed2TXT - https://github.com/AveYo/Compressed2TXT

:Start
	@echo off
	Title DK
	Color 0f
	chcp 866 >nul	
rem �஢��塞, �⮡� � ��� �� �뫮 ᪮��� ��� ��᪫��⥫쭮�� �����, ����蠥� �ࠢ� �� ����������� ⥪�騩 䠩�
	if not exist "%~dp0Work" echo �� ������� ࠡ��� ����� Work �冷� � �ணࠬ���, �㤥� �믮���� ��室. && timeout /t 7 >nul && exit
	echo "%~dp0" | findstr /r "[()!]" >nul && echo ���� �� .bat ᮤ�ন� �������⨬� ᨬ����, ��ࠢ�� ���� � ������� �ணࠬ�� ����୮. && timeout /t 7 >nul && exit
	SetLocal EnableDelayedExpansion
	cd /d "%~dp0Work"
	reg query "HKU\S-1-5-19" >nul 2>&1 || nircmd elevate "%~f0" && exit

rem ��१���� �� TrustedInstaller
	if /i "%USERNAME%" neq "%COMPUTERNAME%$" NSudoLC -U:T -P:E -UseCurrentConsole %0 && exit

rem Set variable's
	set "ch=cecho.exe"
	set "AlreadyInExclusion="
	set "ArgNsudo="
	set "LGPOtemp=LGPO-temp.txt"
	set "DefenderKey=HKLM\Software\Policies\Microsoft\Windows Defender"

rem ����� � ��� �ணࠬ��
	set Version=12.2.1
	set DateProgram= 09.07.24
	
rem ��ࢮ� �᫮ - �ਭ�, ��஥ - �����
	Mode 80,45
	nircmd win center process cmd.exe & nircmd win settext foreground "DK | v. %Version% | %DateProgram% | By Vlado"
	
rem ����塞 ���㦭� 䠩��
	if exist "%SystemDrive%\latestVersion.bat" del /q "%SystemDrive%\latestVersion.bat"
	if exist 7z.exe del /q 7z.exe
	if exist ToolsForDK.zip del /q ToolsForDK.zip

rem �஢�ઠ nhmb.exe, ToolsForDK
	if not exist nhmb.exe %ch% {0c} ��� 䠩�� nhmb.exe � ����� Work.{\n} ��४�砩� ����� ��娢 DefenderKiller.{\n #}&& timeout /t 5 >nul && exit
	if not exist UnlockerUnpack.bat %ch% {0c} ��� 䠩�� UnlockerUnpack.bat � ����� Work.{\n} ��४�砩� ����� ��娢 DefenderKiller.{\n #}&& timeout /t 5 >nul && exit
	
rem ��㬥�� ��� NSUDO � ����ᨬ��� �� ���ﭨ� UAC [C - �᫨ �⪫��� / E - �᫨ ������]
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" | find /i "0x0" >nul 2>&1 && set "ArgNsudo=C" || set "ArgNsudo=E"
	if not exist "%SystemRoot%\System32\smartscreen.exe" (set "SmartScreen=0a") else (set "SmartScreen=0c")
	if not exist "%SystemRoot%\System32\gpedit.msc" set "NoGP=Yes"

rem ������ / ��㦡� � �ࠩ���
	for %%p in (MsMpEng SgrmBroker uhssvc NisSrv MpCmdRun MPSigStub SecHealthUI SecurityHealthSystray SecurityHealthService SecurityHealthHost MpDefenderCoreService) do (
	qprocess "%%~p.exe" >nul 2>&1 && set "%%~p=0c" || set "%%~p=0a")
	for %%x in (WinDefend WdNisSvc Sense wscsvc SgrmBroker SecurityHealthService webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent wtd MsSecWfp MsSecFlt MsSecCore) do sc query "%%~x" >nul 2>&1 && set "%%~x=0c" || set "%%~x=0a"

rem ���� � ����� ����� �����஢騪�
	set PathTask=%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender
	if not exist "%PathTask%\Windows Defender Cache Maintenance" (set "Maintenance=0a") else (set "Maintenance=0c")
	if not exist "%PathTask%\Windows Defender Scheduled Scan" (set "Scan=0a") else (set "Scan=0c")
	if not exist "%PathTask%\Windows Defender Verification" (set "Verification=0a") else (set "Verification=0c")
	if not exist "%PathTask%\Windows Defender Cleanup" (set "Cleanup=0a") else (set "Cleanup=0c")
	if not exist "%SystemRoot%\System32\Tasks\Microsoft\Windows\AppID\SmartScreenSpecific" (set "SmartScreenSpecific=0a") else (set "SmartScreenSpecific=0c")

rem ��砫� ���� �ணࠬ�� ��᫥ ��� �஢�ப
	%ch% {09}����ﭨ� ����ᮢ ���⭨��:{\n #}
	%ch% {%SmartScreen%} SmartScreen {08}[Windows Defender SmartScreen]{\n #}
	%ch% {%MsMpEng%} MsMpEng    {08} [Antimalware Service Executable]{\n #}
	%ch% {%SgrmBroker%} SgrmBroker  {08}[�ப�� �।� �믮������ System Guard]{\n #}
	%ch% {%uhssvc%} uhssvc     {08} [Microsoft Update Health Service]{\n #}
	%ch% {%NisSrv%} NisSrv     {08} [Network Realtime Inspection]{\n #}
	%ch% {%MpCmdRun%} MpCmdRun   {08} [Microsoft malware protection]{\n #}
	%ch% {%MPSigStub%} MPSigStub{08}   [Malware Protection Signature Update Stub]{\n #}
	%ch% {%SecHealthUI%} SHealthUI{08}   [���� ������᭮��� Windows]{\n #}
	%ch% {%SecurityHealthSystray%} HealthTray{08}  [������ ������᭮�� � �॥]{\n #}
	%ch% {%SecurityHealthService%} HealthServ{08}  [SecurityHealthService]{\n #}
	%ch% {%SecurityHealthHost%} HealthHost{08}  [SecurityHealthHost]{\n #}
	%ch% {%MpDefenderCoreService%} CoreService{#}{08} [Antimalware Core Service]{\n #}{\n #}

	%ch% {09}����ﭨ� �㦡 � �ࠩ��஢ ���⭨��:{\n #}
rem 	��㦡�
	%ch% {%WinDefend%} WinDefend  {08} [��㦡� ��⨢���᭠� �ணࠬ�� ���⭨�� Windows]{\n #}
	%ch% {%WdNisSvc%} WdNisSvc {08}   [��㦡� �஢�ન �� Windows Defender Antivirus]{\n #}
	%ch% {%Sense%} Sense      {08} [��㦡� Advanced Threat Protection]{\n #}
	%ch% {%wscsvc%} wscsvc      {08}[��㦡� ����� ���ᯥ祭�� ������᭮��]{\n #}
	%ch% {%SgrmBroker%} SgrmBroker  {08}[��㦡� �ப�� �����ਭ�� �।� �믮������ System Guard]{\n #}
	%ch% {%SecurityHealthService%} SHealthSer  {08}[��㦡� ����� ������᭮�� ���⭨�� Windows]{\n #}
	%ch% {%webthreatdefsvc%} webthreat   {08}[��㦡� ����� �� ���-�஧ - webthreatdefsvc]{\n #}
	%ch% {%webthreatdefusersvc%} webthreatu  {08}[��㦡� ����� ���짮���. �� ���-�஧ - webthreatdefusersvc]{\n #}
rem 	�ࠩ����
	%ch% {%WdNisDrv%} WdNisDrv    {08}[�ࠩ��� WD Network Inspection Driver]{\n #}
	%ch% {%WdBoot%} WdBoot      {08}[�ࠩ��� WD Antivirus Boot Driver]{\n #}
	%ch% {%WdFilter%} WdFilter{#}{08}    [�ࠩ��� WD Antivirus Mini-Filter Driver]{\n #}
	%ch% {%SgrmAgent%} SgrmAgent{#}{08}   [�ࠩ��� System Guard Runtime Monitor Agent Driver]{\n #}
	%ch% {%wtd%} wtd{#}{08}         [�ࠩ��� WTD Driver]{\n #}
	%ch% {%MsSecWfp%} MsSecWfp{#}{08}    [�ࠩ��� Microsoft Security WFP Callout Driver]{\n #}
	%ch% {%MsSecFlt%} MsSecFlt{#}{08}    [�ࠩ��� Security Events Component Minifilter]{\n #}
	%ch% {%MsSecCore%} MsSecCore{#}{08}   [�ࠩ��� Microsoft Security Core Boot Driver]{\n #}
	
	echo.

	%ch% {09}����ﭨ� ������� � �����஢騪�:{\n #}
	%ch% {%Maintenance%} Windows Defender Cache Maintenance{\n #}
	%ch% {%Scan%} Windows Defender Scheduled Scan{\n #}
	%ch% {%Verification%} Windows Defender Verification{\n #}
	%ch% {%Cleanup%} Windows Defender Cleanup{\n #}
	%ch% {%SmartScreenSpecific%} SmartScreenSpecific{\n #}
	
	echo.
	
	%ch% {0f} 1 - {04}������� ���⭨�{\n #}
	%ch% {0f} 2 - {08}�஢���� ���ﭨ� ����� � 䠩��� ���⭨��{\n #}
	%ch% {0f} 3 - {08}�஢���� ����������{\n #}
	%ch% {0f} 4 - {0e}����⠭�������, 㤠����� ������᭮��{\n #}
	
	set "input="
	set /p input=
	if not defined input  cls && goto Start
	if "%input%"=="1"  cls && goto DeleteDefender
	if "%input%"=="2"  cls && goto Catalogs
	if "%input%"=="3"  cls && goto CheckUpdate
	if "%input%"=="4"  cls && goto ManageDefender
	cls & %ch%    {0c}����� �㭪樨 �� �������{\n #}
	timeout /t 2 >nul && cls && goto Start

:DeleteDefender
rem �஢�ઠ ࠧ�來���
	set xOS=x64& (if "%processor_architecture%"=="x86" if not defined PROCESSOR_ARCHITEW6432 Set xOS=x86)

rem ��������� ���� �� ��᪥ � ������� vbs
	reg delete "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /f >nul 2>&1
	set "sFreeSize=" & set "sFreeSize1=" & set "CountFreeSize="
	echo Set objWMIService = GetObject("winmgmts:\\.\root\cimv2") > temp.vbs
	echo Set colItems = objWMIService.ExecQuery^ _ >> temp.vbs
	echo    ("Select FreeSpace from Win32_LogicalDisk Where DeviceID = '%SystemDrive%'") >> temp.vbs
	echo For Each objItem in colItems >> temp.vbs
	echo    FreeMegaBytes = CLng(objItem.FreeSpace / 1048576) >> temp.vbs
	echo Next >> temp.vbs
	echo WScript.Echo FreeMegaBytes >> temp.vbs
	for /f %%i in ('cscript //nologo temp.vbs') do set sFreeSize=%%i

rem �᫨ ������� Windows Defender,
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (
	
rem �஢��塞, ���� �� १�ࢭ�� �����. �᫨ १�ࢭ�� ����� ��� - �।������ ᮧ����.
	if not exist "%SystemDrive%\WDefenderBackup" (
		nhmb "������� १�ࢭ�� ����� ��। 㤠������?\n����� �㤥� ����⠭����� ���⭨� � ������� �����.\n\n�롨ࠩ� ���, ⮫쪮 � ⮬ ��砥, �᫨ �� �� �������� ���������ﬨ Windows." "CreateBackupWD" "Warning|YesNo|DefButton2"
		if errorlevel 7 goto SkipCreateBackup
		if errorlevel 6 call :CreateBackupDefender)
	
:SkipCreateBackup
rem SmartScreen / ����������� �� 業�� ������᭮��. NSudo - ��� ��������� �ࠢ, �.�. �� ���᮫� ����饭� �� TI � ��⪠ HKCU ��� TI.
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nu
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul
	
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >null

rem MSRT - �।�⢮ 㤠����� �।������ �ணࠬ� �� Microsoft. [�� ��ࠢ���� ������ �� MSRT/�⪫���� ����祭�� ���������� ��� MSRT]
	reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul
	reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul
	)
	
rem �ய�� Unlocker; DefenderStop, �᫨ ��� ����� 㦥 㤠����
		if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
    if not exist "%SystemDrive%\Program Files\Windows Defender" (
        goto DefenderAlreadyDeleted
		)
	)

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

rem ������塞 � �᪫�祭�� [� ᠬ�� ��⮤� ���� �஢�ઠ �� ����୮� ���������� � �᪫�祭��]
	call :AddExclusion
	nircmd win settext foreground "DK"

rem �����蠥� ������
	for %%x in (MpCmdRun MpDefenderCoreService MsMpEng SecurityHealthSystray SecurityHealthService SecurityHealthHost smartscreen SgrmBroker SecHealthUI uhssvc NisSrv MPSigStub MSASCuiL MRT) do nircmd killprocess "%%~x"

rem ��ᯠ����� Unlocker � ������� .bat Compressed2TXT
	NSudoLC -U:P -ShowWindowMode:Hide -Wait UnlockerUnpack.bat
	
	%ch%    {08} �஢����� �������{\n #}
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait cmd.exe /c taskkill /f /im explorer.exe >nul 2>&1
	%ch%    {0c} �믮��塞 㤠����� � ������� Unlocker by Eject{\n #}{\n #}
	Unlocker /DeleteDefender

:CheckFolder
	if exist "%Temp%\IObitUnlocker\IObitUnlocker.exe" goto CheckFolder
	
rem �஢��塞 ��᫥ 㤠�����, ��⠫��� �� �����. �᫨ ��⠫��� - �믮��塞 ����୮� 㤠����� � ������� Unlocker
	for %%d in ("%AllUsersProfile%\Microsoft\Windows Security Health", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender") do (
		if exist %%d (
			%ch%    {08} ����� %%d �� 㤠������{\n #}
			%ch%    {0c} �������� %%d{\n #}{\n #}
			timeout /t 2 /nobreak >nul
			Unlocker /DeleteDefender
		)
	)
	
rem ����� �஢������
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c start explorer.exe >nul 2>&1
	
rem �ਬ��塞 �᭮���� ����⨪� �� �⪫�祭�� ���⭨�� 㦥 ��᫥ 㤠�����, �᫨ �� �� HOME �����, ��� ��� �᭠�⪨ ��㯯���� ����⨪.
rem �ਬ������ ����⨪� - ����易⥫쭮� ����⢨� �� ������ �⠯�, ��᪮��� ���⭨� 㤠��. ����⨪� - '�����誠'. �� ����稥 ����易⥫쭮.
rem �ॡ���� ⮫쪮 ��� ⮣�, �⮡� ��㣮� ���, ����� �஢���� ���ﭨ� ���⭨�� �� ������� ��ࠬ���� ��⠫, �� ���⭨� 㦥 �⪫���
rem �ਬ������ ������ ����⨪� �� ��᫥���� ������ Windows 11, �������� 㦥 � Windows 10 ���������� ��। 㤠������ ���⭨��, �.�. Microsoft �� �ਬ������ �⮩ ����⨪� �����⠫쭮 �������� ����� �ணࠬ� � ࠡ��� ��.
rem ��᫥������� - https://azuretothemax.net/2023/05/01/murdering-windows-11-performance-by-disabling-windows-defender-what-not-to-do/
	if not defined NoGP (
		call :LGPOFILE reg add "%DefenderKey%" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
		call :LGPO_APPLY >nul 2>&1
		nircmd win activate process cmd.exe
	)

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:DefenderAlreadyDeleted
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" %ch%    {03} ����塞 ����� � 䠩�� ���⭨��{\n #}{\n #}
(
rem ProgramData
	rd /s /q "%AllUsersProfile%\Microsoft\Windows Defender"
	rd /s /q "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection"
	rd /s /q "%AllUsersProfile%\Microsoft\Windows Security Health"
	rd /s /q "%AllUsersProfile%\Microsoft\Storage Health"

	rd /s /q "%SystemDrive%\Program Files\Windows Defender"
	rd /s /q "%SystemDrive%\Program Files\Windows Defender Sleep"
	rd /s /q "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection"
	rd /s /q "%SystemDrive%\Program Files\Windows Security"
	rd /s /q "%SystemDrive%\Program Files\PCHealthCheck"
	rd /s /q "%SystemDrive%\Program Files\Microsoft Update Health Tools"

	rd /s /q "%SystemDrive%\Program Files (x86)\Windows Defender"
	rd /s /q "%SystemDrive%\Program Files (x86)\Windows Defender Advanced Threat Protection"

	rd /s /q "%SystemRoot%\security\database"
	rd /s /q "%SystemRoot%\System32\HealthAttestationClient"
	rd /s /q "%SystemRoot%\System32\SecurityHealth"
	rd /s /q "%SystemRoot%\System32\WebThreatDefSvc"
	rd /s /q "%SystemRoot%\System32\Sgrm"
	rd /s /q "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender"
	rd /s /q "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	rd /s /q "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender"
	rd /s /q "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender"
	rd /s /q "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender"
	rd /s /q "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	
	if exist "%AllUsersProfile%\Microsoft\Windows Defender\Platform" (
	for /r "%AllUsersProfile%\Microsoft\Windows Defender\Platform" %%i in ("MpOAV.dll") do ren "%%i" "MpOAV.dll_fuck"
	for /r "%AllUsersProfile%\Microsoft\Windows Defender\Platform" %%i in ("MpClient.dll") do ren "%%i" "MpClient.dll_fuck"
	for /r "%AllUsersProfile%\Microsoft\Windows Defender\Platform" %%i in ("MsMpEng.exe") do ren "%%i" "MsMpEng.exe_fuck")
	
	if exist "%SystemDrive%\Program Files\Windows Defender" (
	ren "%SystemDrive%\Program Files\Windows Defender\MpOAV.dll" "MpOAV.dll_fuck"
	ren "%SystemDrive%\Program Files\Windows Defender\MpClient.dll" "MpClient.dll_fuck"
	ren "%SystemDrive%\Program Files\Windows Defender\MsMpEng.exe" "MsMpEng.exe_fuck")

	ren "%SystemRoot%\System32\SecurityHealthService.exe" "SecurityHealthService.exe_fuck"
	ren "%SystemRoot%\System32\smartscreenps.dll" smartscreenps.dll_fuck
	ren "%SystemRoot%\System32\wscapi.dll" wscapi.dll_fuck

rem WindowsDefenderApplicationGuard.wim
	del /f /q "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim"
	del /f /q "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim"
	
rem �������� 䠩��� System32
	del /f /q "%SystemRoot%\System32\SecurityHealthService.exe"
	del /f /q "%SystemRoot%\System32\SecurityHealthService.exe_fuck"
	del /f /q "%SystemRoot%\System32\SecurityHealthSystray.exe"
	del /f /q "%SystemRoot%\System32\SecurityHealthHost.exe"
	del /f /q "%SystemRoot%\System32\SecurityHealthAgent.dll"
	del /f /q "%SystemRoot%\System32\SecurityHealthSSO.dll"
	del /f /q "%SystemRoot%\System32\SecurityHealthProxyStub.dll"
	del /f /q "%SystemRoot%\System32\LogFiles\WMI\RtBackup\EtwRTDefenderApiLogger.etl"
	del /f /q "%SystemRoot%\System32\LogFiles\WMI\RtBackup\EtwRTDefenderAuditLogger.etl"
	del /f /q "%SystemRoot%\System32\smartscreen.dll"
	del /f /q "%SystemRoot%\System32\wscisvif.dll"
	del /f /q "%SystemRoot%\System32\wscproxystub.dll"
	del /f /q "%SystemRoot%\System32\smartscreenps.dll"
	del /f /q "%SystemRoot%\System32\smartscreenps.dll_fuck"
	del /f /q "%SystemRoot%\System32\wscapi.dll"
	del /f /q "%SystemRoot%\System32\wscapi.dll_fuck"
	del /f /q "%SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll"
	del /f /q "%SystemRoot%\System32\wscsvc.dll"
	del /f /q "%SystemRoot%\System32\SecurityHealthCore.dll"
	del /f /q "%SystemRoot%\System32\SecurityHealthSsoUdk.dll"
	del /f /q "%SystemRoot%\System32\SecurityHealthUdk.dll"
	
rem �������� SmartScreen.exe
	taskkill /f /im smartscreen.exe
	ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen.exedel"
	del /f /q "%SystemRoot%\System32\smartscreen.exe"
	del /f /q "%SystemRoot%\System32\smartscreen.exedel"
	
rem �������� 䠩��� SysWOW64
	del /f /q "%SystemRoot%\SysWOW64\smartscreen.dll"
	del /f /q "%SystemRoot%\SysWOW64\wscisvif.dll"
	del /f /q "%SystemRoot%\SysWOW64\wscproxystub.dll"
	del /f /q "%SystemRoot%\SysWOW64\smartscreenps.dll"
	del /f /q "%SystemRoot%\SysWOW64\wscapi.dll"
	del /f /q "%SystemRoot%\SysWOW64\windowsdefenderapplicationguardcsp.dll"
) >nul 2>&1
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (
	%ch%    {03} ����塞 �㦡� � �ࠩ���{\n #}
	%ch%    {0a} WinDefend, SecurityHealthService, Sense, WdNisSvc, wscsvc, webthreatdefsvc{\n #}
	%ch%    {0a} WdNisDrv, WdBoot, WdFilter, SgrmAgent, wtd, MsSecWfp, MsSecFlt, MsSecCore{\n #}{\n #}
	)
	
	for %%x in (WinDefend WdNisSvc Sense wscsvc SgrmBroker SecurityHealthService webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent wtd MsSecWfp MsSecFlt MsSecCore) do (
	sc stop "%%~x" >nul 2>&1
	sc delete "%%~x" >nul 2>&1
	reg delete "HKLM\System\CurrentControlset\Services\%%~x" /f >nul 2>&1
	rd /s /q "%SystemRoot%\System32\drivers\wd" >nul 2>&1)

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (
	%ch%    {03} ����塞 ������� �� �����஢騪�{\n #}
	%ch%    {0a} Windows Defender Cache Maintenance{\n #}
	%ch%    {0a} Windows Defender Cleanup{\n #}
	%ch%    {0a} Windows Defender Scheduled Scan{\n #}
	%ch%    {0a} Windows Defender Verification{\n #}
	%ch%    {0a} SmartScreenSpecific{\n #}{\n #}
	)

(
rem �������� ����� �����஢騪�
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /f
	schtasks /Delete /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /f

rem �������� ��⪨ Windows Defender �� ॥���
	reg delete "HKLM\Software\Microsoft\Windows Defender" /f
	reg delete "HKLM\Software\Microsoft\Windows Defender Security Center" /f
	reg delete "HKLM\Software\Microsoft\Windows Advanced Threat Protection" /f
	reg delete "HKLM\Software\Microsoft\Windows Security Health" /f

	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" /f
	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" /f

rem ���⪠ ���⥪�⭮�� ����
	reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" /v "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f

rem �������� �� ��⮧���᪠
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /f
	
rem �������� ������ � ��ࠬ����
	reg delete "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" /f
	
rem �������� ��ୠ��� ᮡ�⨩
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" /f

rem �������� �� ������ �ࠢ����� ����� Windows Defender [Windows 8.1]
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	reg delete "HKCR\CLSID\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	
) >nul 2>&1

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

rem �᫨ 㤠�﫠�� �� ��⪠ ࠭��, �ய�᪠�� 㤠����� ����� �� WinSxS
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" >nul 2>&1 && (
rem �஢��塞 ᮧ������� �� ���, �᫨ ��� - ��訢��� �筮 �� 㤠���� ����� �� WinSxS
	reg query "HKLM\Software\DefenderKiller" >nul 2>&1 && (
		echo >nul
	) || (
		nhmb "�� �� ᮧ���� १�ࢭ�� �����.\n\n�������� ����� � WinSxS ����� ������� ��⠭���� �������� ���������� Windows!\n\n������� ����� Windows Defender �� WinSxS?" "DK" "Warning|YesNo|DefButton2"
	if errorlevel 7 (
		%ch%    {0e} �� �ய��⨫� 㤠����� ����� �� WinSxS{\n #}
		%ch%    {08} ��� ����� ����� �� ᫥���饬 㤠�����{\n #}{\n #}
		goto FinishDelete)
	if errorlevel 6 echo >nul
	)
	
	%ch%    {03} ����塞 ����� �� WinSxS{\n #}{\n #}
	for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*windows-defender*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*windows-senseclient-service*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*windows-dynamic-image*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	)

rem �������� ��⪨ ��᫥ 㤠����� ����� �� WinSxS. �믮������ ������ ��᫥ 㤠����� ����� �� WinSxS, �⮡� 㤠����� �뫮 �ᥣ� 1 ࠧ.
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /f >nul 2>&1
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:FinishDelete
rem �᢮����񭭮� ���� �� ��᪥
	for /f %%i in ('cscript //nologo temp.vbs') do set sFreeSize1=%%i
	set /a CountFreeSize=%sFreeSize1% - %sFreeSize%
	if defined CountFreeSize %ch%    {0c} %CountFreeSize% MB {0f}�᢮������� �� ��᪥ %SystemDrive%\ ��᫥ 㤠�����{\n #}
	
rem ����塞 Unlocker, ��� �ࠩ��� � ��⠫�� 䠩��. �ࠩ��� ����⠭������ ᠬ, �᫨ �ᯮ������ ��⠭����� IObitUnlocker
(
	del /q Unlocker.exe
	del /q DefenderStopx86.exe
	del /q DefenderStopx64.exe
	del /q temp.vbs
	del /q "%SystemRoot%\unlocker.log"
	rd /s /q "%AllUsersProfile%\IObit"
	sc delete IObitUnlocker
) >nul 2>&1
		
	if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
		if not exist "%SystemDrive%\Program Files\Windows Defender" (
			%ch%    {08} �ਥ������� �� ���ﭨ� ����� {0f}- ��� 2{\n #}
			%ch%    {08} ������ - 㤠����. ���� - �� 㤠����.{\n #}
			%ch%    {0e} �᫨ ��-� �� 㤠������ - ��१���㧨� �� � ������ ����� 㤠�����.{\n #}{\n #}
			reg query "HKLM\System\CurrentControlset\Services\WinDefend" >nul 2>&1 && %ch%    {04} �� �㦡� ���⭨�� �� 㤠����.{\n #}{08}    ������ 㤠����� ��᫥ ��१���㧪� ��.{\n #}{\n #}
			%ch%    {08} ������ ���� ������� ��� ������ � ������� ����.{\n #}
			pause>nul && cls && goto Start
		)
	)
	
	echo.
	nhmb "���⭨� Windows �� 㤠��.\n�᫨ ������ �� ᮮ�饭�� ��᪮�쪮 ࠧ, �믮���� ��१���㧪� �������� � ������ ������ 㤠�����.\n\n������� 㤠����� ���⭨��?\n" "DK" "Information|YesNo"
	if errorlevel 7 cls && goto Start
	if errorlevel 6 cls && set "AlreadyInExclusion=Yes" && goto DeleteDefender
			
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:ManageDefender
	%ch% {\n #}{08} 1{#} - ����⠭����� ���⭨� �� �����{\n #}
	%ch% {08} 2{#} - �ਬ�����/�⪠��� ��㯯��� ����⨪�{\n #}
	%ch% {08} 3{#} - ������� �ਫ������ ������᭮��� [���箪 � ��᪥] [� ���⢥ত�����]{\n #}
	echo.
	%ch% {0e} [Enter]{#} - {08}�������� � ������� ����{\n #}
	set "input="
	set /p input=
	if not defined input	  cls && goto Start
	if "%input%"=="1"    goto RestoreDefender
	if "%input%"=="2"    goto GroupPolicyWD
	if "%input%"=="3"    goto SecHealthUI
	cls && goto ManageDefender

:RestoreDefender
rem ��� ���४⭮�� �⮡ࠦ���� ����������� ����, �.�. �ணࠬ�� ����饭� �� TI
	if not exist "%SystemRoot%\System32\config\systemprofile\Desktop" md "%SystemRoot%\System32\config\systemprofile\Desktop"
	
	%ch% {0c} ��������, �� ��࠭��� १. ����� �뫠 ᮧ���� �� �⮩ �� ���ᨨ Windows{\n #}
	
	set "BackupFolder="
	for /f %%a in ('powershell -c "(New-Object -COM 'Shell.Application').BrowseForFolder(0, '�롥�� ����� WDefenderBackup � ࠭�� ᮧ������ १�ࢭ�� ������ Windows Defender. ��᫥ �롮� ����� �㤥� ����� ����� � ����⠭������� ���⭨��.', 0, 0).Self.Path"') do set "BackupFolder=%%a"
	echo.
	if not defined BackupFolder cls && goto ManageDefender
	if not exist "%BackupFolder%\Folder" %ch%    {04} ����ୠ� १�ࢭ�� �����. �롥�� �ࠢ����� १�ࢭ�� �����.{\n #}&&timeout /t 3 >nul && cls && goto ManageDefender
	if not exist "%BackupFolder%\ServicesDrivers" %ch%    {04} ����ୠ� १�ࢭ�� �����. �롥�� �ࠢ����� १�ࢭ�� �����.{\n #}&&timeout /t 3 >nul && cls && goto ManageDefender
	
	%ch% {03} ����⠭������� ���⭨��{\n #}{\n #}
	pushd "%BackupFolder%"
(
	copy /y "Files\System32" "%SystemRoot%\System32"
	copy /y "Files\SysWOW64" "%SystemRoot%\SysWOW64"
	copy /y "Files\Windows\Containers\WindowsDefenderApplicationGuard.wim" "%SystemRoot%\Containers\"
	copy /y "Files\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim" "%SystemRoot%\Containers\serviced"
	
	xcopy "Folder\Program Files\*" "%ProgramFiles%\" /E /H /K /Y
	xcopy "Folder\Program Files (x86)\*" "%ProgramFiles(x86)%\" /E /H /K /Y
	xcopy "Folder\ProgramData\*" "%ProgramData%\" /E /H /K /Y
	xcopy "Folder\System32\*" "%SystemRoot%\System32" /E /H /K /Y
	xcopy "Folder\SysWow64\*" "%SystemRoot%\SysWow64" /E /H /K /Y
	xcopy "Folder\Windows\*" "%SystemRoot%\" /E /H /K /Y
	xcopy "Folder\WinSxS\*" "%SystemRoot%\WinSxS\" /E /H /K /Y

rem ����⠭������� ॥���/�㦡, �ࠩ��஢
	for %%f in ("RegEdit\*.reg") do reg import "%%f"
	for %%f in ("ServicesDrivers\*.reg") do reg import "%%f"

rem ����⠭������� SmartScreen.exe
	if exist "%SystemRoot%\System32\smartscreen_disabled.exe" rename "%SystemRoot%\System32\smartscreen_disabled.exe" "smartscreen.exe"

rem ����塞 ࠧ��� �� ���஬� �஢������ ᮧ���� �� १�ࢭ�� �����. ������ SysApps ���� 㤠������.
	reg delete "HKLM\Software\DefenderKiller" /f

rem ��頥� �� ���������� ࠭�� ��� � �᪫�祭�� ���⭨��
	reg delete "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" /f
	
rem ����⠭������� ��ࠬ��஢ ॥���
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /f
	reg delete "HKLM\Software\Policies\Microsoft\MRT" /f
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f
) >nul 2>&1

	popd
	
	call :RestoreGP
	timeout /t 1 /nobreak >nul
	call :RestoreGP
	nhmb "�ॡ���� ��१���� ��" "DK" "Information|Ok"
	cls && goto Start

:GroupPolicyWD
	if not exist "%SystemRoot%\System32\gpedit.msc" %ch%  {04} �� ������� ��, � ��� HOME �����, ���� �����-� ᡮઠ.{\n #}&&timeout /t 3 >nul && cls && goto ManageDefender
	%ch% {\n #}{0f} 1{#} - {0f}�ਬ����� ��㯯��� ����⨪� ���⭨��{\n #}
	%ch% {0f} 2{#} - {0f}�⪠��� ��㯯��� ����⨪� ���⭨��{\n #}
	%ch% {0f} 3{#} - {08}�⬥���� �롮�{\n #}
	
	set "input="
	set /p input=
	if not defined input  cls && goto ManageDefender
	if "%input%"=="1"  call :ApplyGP & timeout /t 1 /nobreak >nul & call :ApplyGP
	if "%input%"=="2"  call :RestoreGP & timeout /t 1 /nobreak >nul & call :RestoreGP
	if "%input%"=="3"  cls && goto ManageDefender
	cls && goto ManageDefender
	
:ApplyGP
	call :LGPOFILE reg add "%DefenderKey%" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "LocalSettingOverrideDisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Spynet" /v "**del.SpynetReporting" /t REG_SZ /d " " /f
	call :LGPOFILE reg add "%DefenderKey%\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
	call :LGPOFILE reg add "%DefenderKey%\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "%DefenderKey%\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "%DefenderKey%\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f
	call :LGPOFILE reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
	call :LGPOFILE reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "**del.ShellSmartScreenLevel" /t REG_SZ /d " " /f
	call :LGPOFILE reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
	call :LGPO_APPLY
	nircmd win activate process cmd.exe
	exit /b

:RestoreGP
rem ����⠭������� ����⨪
	call :LGPOFILE reg delete "%DefenderKey%" /v "DisableAntiSpyware" /f
	call :LGPOFILE reg delete "%DefenderKey%" /v "ServiceKeepAlive" /f
	call :LGPOFILE reg delete "%DefenderKey%" /v "DisableRoutinelyTakingAction" /f
	call :LGPOFILE reg delete "%DefenderKey%" /v "AllowFastServiceStartup" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "DisableRealtimeMonitoring" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "DisableIOAVProtection" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "DisableBehaviorMonitoring" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "DisableOnAccessProtection" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "LocalSettingOverrideDisableRealtimeMonitoring" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /f
	call :LGPOFILE reg delete "%DefenderKey%\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /f
	call :LGPOFILE reg delete "%DefenderKey%\Spynet" /v "LocalSettingOverrideSpynetReporting" /f
	call :LGPOFILE reg delete "%DefenderKey%\Spynet" /v "**del.SpynetReporting" /f
	call :LGPOFILE reg delete "%DefenderKey%\Spynet" /v "SubmitSamplesConsent" /f
	call :LGPOFILE reg delete "%DefenderKey%\Spynet" /v "**del.SubmitSamplesConsent" /f
	call :LGPOFILE reg delete "%DefenderKey%\Signature Updates" /v "RealtimeSignatureDelivery" /f
	call :LGPOFILE reg delete "%DefenderKey%\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /f
	call :LGPOFILE reg delete "%DefenderKey%\Signature Updates" /v "UpdateOnStartUp" /f
	call :LGPOFILE reg delete "%DefenderKey%\Signature Updates" /v "DisableScanOnUpdate" /f
	call :LGPOFILE reg delete "%DefenderKey%\Reporting" /v "DisableGenericRePorts" /f
	call :LGPOFILE reg delete "%DefenderKey%\Scan" /v "DisableCatchupFullScan" /f
	call :LGPOFILE reg delete "%DefenderKey%\Scan" /v "DisableCatchupQuickScan" /f
	call :LGPOFILE reg delete "%DefenderKey%\Scan" /v "DisableRemovableDriveScanning" /f
	call :LGPOFILE reg delete "%DefenderKey%\Scan" /v "DisableScanningNetworkFiles" /f
	call :LGPOFILE reg delete "%DefenderKey%\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /f
	call :LGPOFILE reg delete "%DefenderKey%\Scan" /v "DisableArchiveScanning" /f
	call :LGPOFILE reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /f
	call :LGPOFILE reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "**del.ShellSmartScreenLevel" /f
	call :LGPOFILE reg delete "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /f
	call :LGPO_APPLY
	nircmd win activate process cmd.exe
	exit /b
	
:SecHealthUI
	ver | findstr /c:"6.3" /c:"6.2" /c:"6.1" >nul && %ch%    {04} �� �ॡ���� �� ������ ���ᨨ Windows{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender

rem ����砥� SID
	set "SID="
	for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoLogonSID" 2^>nul') do set "SID=%%a"
	if not defined SID for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v "LastLoggedOnUserSID" 2^>nul') do set "SID=%%a"
	if not defined SID %ch%    {04} SID �� �� ����祭, �⬥�� 㤠����� �ਫ������{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender
	
	%ch% {\n} ��᫥ 㤠����� �ਫ������ ���� � ����ன�� ���⭨�� �㤥� {04}����������.{\n #}
	%ch% {08} 1.{#} {0c}������� �ਫ������{\n #}
	%ch% {08} 2.{#} {08}�⬥��{\n #}
	choice /c 12 /n /m " "
	if errorlevel 2 cls && goto ManageDefender
	
rem ����砥� ��� SystemApp ������᭮��� Windows [SecHealthUI] - �᭠�⪠ ��� �ࠢ����� ��⨢���᭮� �ணࠬ��� Windows Defender
	%ch%    {03} ����塞 ������᭮��� Windows{\n #}
	set "NameSecHealth="
	for /F "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*SecHealthUI*" /k^|findstr ^H`) do set NameSecHealth=%%~nxn
	if not defined NameSecHealth %ch%    {02} �ਫ������ ������᭮��� Windows 㤠����{\n #}{\n #}&& goto AppRepSys

	%ch% {08} %NameSecHealth%{\n #}{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameSecHealth%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameSecHealth%" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *SecHealthUI* | Remove-AppxPackage"
	NSudoLC -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *SecHealthUI* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*SecHealthUI*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem �� ����� ����� 㤠����. ����⠭���������� ᠬ�, �᫨ ����⠭����� �ਫ������ ������᭮���.
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"

:AppRepSys
rem ����砥� ��� SystemApp AppRep [SmartScreen]
	%ch%    {03} ����塞 SmartScreen ���⭨�� Windows{\n #}
	set "NameAppRep="
	for /F "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do set NameAppRep=%%~nxn
	if not defined NameAppRep %ch%    {02} �ਫ������ SmartScreen ���⭨�� Windows 㤠����{\n #}&& pause && cls && goto ManageDefender

	%ch% {08} %NameAppRep%{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameAppRep%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameAppRep%" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *Apprep.ChxApp* | Remove-AppxPackage"
	NSudoLC -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *Apprep.ChxApp* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem �� ����� ����� 㤠����, ����⠭���������� ᠬ�, �᫨ ����⠭����� �ਫ������ Apprep.ChxApp
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	
	pause && cls && goto ManageDefender

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:AddExclusion
	if defined AlreadyInExclusion (
	%ch%    {08} �ய�� ���������� � �᪫�祭�� ���⭨�� [㦥 ���������]{\n #}{\n #}
	exit /b)
	%ch%    {03} ������塞 � �᪫�祭�� ���⭨��{\n #}{\n #}
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-PSDrive -PSProvider 'FileSystem' | ForEach-Object { Add-MpPreference -ExclusionPath $_.Root }" >nul 2>&1
	set "AlreadyInExclusion=Yes"
	timeout /t 2 /nobreak >nul
	exit /b
		
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

rem ������� WestLife/AutoSettings - https://disk.yandex.ru/d/CMqvcp1F3QiaWL
:LGPOFILE
	setlocal
	if /i "%~2" NEQ "delete" if /i "%~2" NEQ "add" (
	 %ch%     {0c}�ய�� ���������� ��ࠬ��� � LGPO 䠩�, ���ࠢ��쭠� �������{#}:{\n #} & %ch%    %1 {0e}%2{#} %3 {\n #} & exit /b)
	 
	if /i "%~2" EQU "delete" if "%~7" NEQ "" (
	 %ch%     {0c}�ய�� ���������� ��ࠬ��� � LGPO 䠩�, �訡�� � ��ࠬ���{#}:{\n #} & echo.   %1 %2 %3 & %ch%        %4 %5 %6 {0e}%7 %8 %9 {\n #}& exit /b)
	 
	set "RegType=%~7:"
	set "RegType=%RegType:REG=%"
	set "RegType=%RegType:_=%"
	set "RegType=%RegType:PAND=%"
	if "%~3" NEQ "" for /f "tokens=1* delims=\" %%I in ("%~3") do ( set "RegKey=%%J"
	 if /i "%%I" EQU "HKEY_LOCAL_MACHINE" (set Config=Computer) else if /i "%%I" EQU "HKLM" (set Config=Computer
	 ) else if /i "%%I" EQU "HKEY_CURRENT_USER" (set Config=User) else if /i "%%I" EQU "HKCU" (set Config=User
	 ) else (%ch%     {0c}�ய�� ���������� ��ࠬ��� � LGPO 䠩�, ������ ࠧ���{#}: {0e}"%%I"{\n #} & %ch%    %1 %2 %3 {\n #} & exit /b))
	 
	if "%~9" NEQ "" set "Action=%RegType%%~9"
	if /i "%~6" EQU "/d" set "Action=SZ:%~7"
	if /i "%~2" EQU "delete" set "Action=DELETE"
	if "%~5" EQU "" ( set "Action=DELETEALLVALUES" & set "ValueName=*" ) else ( set "ValueName=%~5" )
	if /i "%~2" EQU "add" if /i "%~4" EQU "/f" set "Action=CREATEKEY" & set "ValueName=*"
	(echo.%Config%& echo.%RegKey%& echo.%ValueName%& echo.%Action%& echo.)>>"%LGPOtemp%"
	exit /b

:LGPO_APPLY
	taskkill /f /im mmc.exe >nul 2>&1
	%ch% {04} �ਬ������ ��{\n #}{\n #}&LGPO.exe /t "%LGPOtemp%" /q
	if exist "%LGPOtemp%" del /f /q "%LGPOtemp%"
	exit /b
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:CheckUpdate
rem �஢�ઠ ������ curl � ����� Work ��� � ����� System32 ��� �஢�ન ����������
		if not exist "%SystemRoot%\System32\curl.exe" (
	if not exist "%~dp0Work\curl.exe" (
	%ch% {04} �ணࠬ�� curl �� ������� � ����� Work � � ����� System32.{\n #}
	%ch% {04} ������� �ணࠬ�� � ����� System32 ��� � Work{\n #}
	%ch% {08} ������ ����� ��� - https://curl.se/windows/{\n #}
	pause && exit))
	
rem �஢��塞 ����稥 ���୥�-ᮥ�������
	ping pastebin.com -n 1 -w 1000 |>nul find /i "TTL="|| cls && %ch% {04} �訡�� �஢�ન, ��� ���୥�-ᮥ�������.{\n #}&&timeout /t 3 >nul && cls && goto Start

rem �஢�ઠ ���������� �ணࠬ��
	curl -g -k -L -# -o "%SystemDrive%\latestVersion.bat" "https://pastebin.com/raw/dnENFgmC" >nul 2>&1
	call "%SystemDrive%\latestVersion.bat"
	if "%Version%" lss "%latestVersion%" (cls) else (
	cls
	%ch% {0a} ���������� �� �������. � ��� ���㠫쭠� ����� {0f}- {0e}%Version%{\n #}{\n #}
	%ch% {08} ��� ������ � ������� ���� ������ ���� �������.{\n #}
	pause >nul
	goto Start)

rem ���������� �ணࠬ��
	%ch%  {0f} ������� ����� �����, ������ ���� ������� �⮡� �������� �ணࠬ��{\n #}
	pause>nul
	curl -g -k -L -# -o %0 "https://github.com/oatmealcookiec/MyProgramm/releases/latest/download/DefenderKiller.bat" >nul 2>&1
	call %0
	cls && exit
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:Catalogs
	%ch% {03}�᭮��� 2 �����{\n #}
	if not exist "%SystemDrive%\Program Files\Windows Defender" (%ch% {02} %SystemDrive%\Program Files\Windows Defender {08}- �᭮���� ����� ���⭨�� 1{\n #}) else (%ch% {04} %SystemDrive%\Program Files\Windows Defender{08} - �᭮���� ����� ���⭨�� 1{\n #})
	if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (%ch% {02} %AllUsersProfile%\Microsoft\Windows Defender {08}- �᭮���� ����� ���⭨�� 2{\n #}) else (%ch% {04} %AllUsersProfile%\Microsoft\Windows Defender{08} - �᭮���� ����� ���⭨�� 2{\n #})
	echo.
	%ch% {09}����� � %SystemRoot%\System32{\n #}
rem 14.03.23
	if not exist "%SystemRoot%\System32\HealthAttestationClient" (%ch% {0a} %SystemRoot%\System32\HealthAttestationClient{\n #}) else (%ch%  {0c}%SystemRoot%\System32\HealthAttestationClient{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealth" (%ch% {0a} %SystemRoot%\System32\SecurityHealth{\n #}) else (%ch%  {0c}%SystemRoot%\System32\SecurityHealth{\n #})
	if not exist "%SystemRoot%\System32\WebThreatDefSvc" (%ch% {0a} %SystemRoot%\System32\WebThreatDefSvc{\n #}) else (%ch%  {0c}%SystemRoot%\System32\WebThreatDefSvc{\n #})
	if not exist "%SystemRoot%\System32\Sgrm" (%ch% {0a} %SystemRoot%\System32\Sgrm{\n #}) else (%ch%  {0c}%SystemRoot%\System32\Sgrm{\n #})
	if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" (%ch% {0a} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender{\n #}) else (%ch%  {0c}%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender{\n #})
	if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" (%ch% {0a} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance{\n #}) else (%ch%  {0c}%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance{\n #})
	if not exist "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" (%ch% {0a} %SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender{\n #}) else (%ch%  {0c}%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender{\n #})
	echo.
	%ch% {09}����� � C:\Program Files{\n #}
	if not exist "%SystemDrive%\Program Files\Windows Defender Sleep" (%ch% {0a} C:\Program Files\Windows Defender Sleep {\n #}) else (%ch%  {4f}C:\Program Files\Windows Defender Sleep{\n #})
	if not exist "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" (%ch% {0a} C:\Program Files\Windows Defender Advanced Threat Protection{\n #}) else (%ch%  {0c}C:\Program Files\Windows Defender Advanced Threat Protection{\n #})
	if not exist "%SystemDrive%\Program Files\Windows Security" (%ch% {0a} C:\Program Files\Windows Security{\n #}) else (%ch%  {0c}C:\Program Files\Windows Security{\n #})
	if not exist "%SystemDrive%\Program Files\PCHealthCheck" (%ch% {0a} C:\Program Files\PCHealthCheck{\n #}) else (%ch%  {0c}C:\Program Files\PCHealthCheck{\n #})
	if not exist "%SystemDrive%\Program Files\Microsoft Update Health Tools" (%ch% {0a} C:\Program Files\Microsoft Update Health Tools{\n #}) else (%ch%  {0c}C:\Program Files\Microsoft Update Health Tools{\n #})
	echo.
	%ch% {09}����� � C:\Program Files (^x86^){\n #}
	if not exist "%ProgramFiles(x86)%\Windows Defender" (%ch% {0a} C:\Program Files (^x86^)\Windows Defender{\n #}) else (%ch%  {0c}C:\Program Files (^x86^)\Windows Defender{\n #})
	if not exist "%ProgramFiles(x86)%\Windows Defender Advanced Threat Protection" (%ch% {0a} C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection{\n #}) else (%ch%  {0c}C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection{\n #})
	echo.
	%ch% {09}����� � C:\ProgramData{\n #}
	if not exist "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" (%ch% {0a} C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection{\n #}) else (%ch%  {0c}C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection{\n #})
	if not exist "%AllUsersProfile%\Microsoft\Windows Security Health" (%ch% {0a} C:\ProgramData\Microsoft\Windows Security Health{\n #}) else (%ch%  {0c}C:\ProgramData\Microsoft\Windows Security Health{\n #})
	if not exist "%AllUsersProfile%\Microsoft\Storage Health" (%ch% {0a} C:\ProgramData\Microsoft\Storage Health{\n #}) else (%ch%  {0c}C:\ProgramData\Microsoft\Storage Health{\n #})
	echo.
	%ch% {09}����� ����� �����஢騪� ���⭨��{\n #}
	if not exist "%SYSTEMROOT%\System32\Tasks\Microsoft\Windows\Windows Defender" (%ch% {0a} C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender{\n #}) else (%ch%  {0c}C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender{\n #})
	echo.		
	%ch% {09}��⠫�� 䠩��{\n #}
	if not exist "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" (%ch% {0a} C:\Windows\Containers\WindowsDefenderApplicationGuard.wim{\n #}) else (%ch%  {0c}C:\Windows\Containers\WindowsDefenderApplicationGuard.wim{\n #})
	if not exist "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" (%ch% {0a} C:\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim{\n #}) else (%ch%  {0c}C:\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealthService.exe" (%ch% {02} SecurityHealthService.exe{#} ^| ) else (%ch% {0c} SecurityHealthService.exe {#}^| )
	if not exist "%SystemRoot%\System32\SecurityHealthSystray.exe" (%ch% {02}SecurityHealthSystray.exe{#} ^| ) else (%ch% {0c}SecurityHealthSystray.exe {#}^| )
	if not exist "%SystemRoot%\System32\SecurityHealthHost.exe" (%ch% {02}SecurityHealthHost.exe{\n #}) else (%ch% {0c}SecurityHealthHost.exe{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealthAgent.dll" (%ch% {02} SecurityHealthAgent.dll{#} ^| ) else (%ch% {0c} SecurityHealthAgent.dll{#} ^| )
	if not exist "%SystemRoot%\System32\SecurityHealthSSO.dll" (%ch% {02}SecurityHealthSSO.dll{#} ^| ) else (%ch% {0c}SecurityHealthSSO.dll{#} ^| )
	if not exist "%SystemRoot%\System32\SecurityHealthProxyStub.dll" (%ch% {02}SecurityHealthProxyStub.dll{\n #}) else (%ch% {0c}SecurityHealthProxyStub.dll{\n #})
	if not exist "%SystemRoot%\System32\smartscreen.dll" (%ch% {02} smartscreen.dll{#} ^| ) else (%ch% {0c} smartscreen.dll{#} ^| )
	if not exist "%SystemRoot%\System32\wscisvif.dll" (%ch% {02}wscisvif.dll{#} ^| ) else (%ch% {0c}wscisvif.dll{#} ^| )
	if not exist "%SystemRoot%\System32\wscproxystub.dll" (%ch% {02}wscproxystub.dll{#} ^| ) else (%ch% {0c}wscproxystub.dll{#} ^| )
	if not exist "%SystemRoot%\System32\smartscreenps.dll" (%ch% {02}smartscreenps.dll{\n #}) else (%ch% {0c}smartscreenps.dll{\n #})
	if not exist "%SystemRoot%\System32\wscapi.dll" (%ch% {02} wscapi.dll{#} ^| ) else (%ch% {0c} wscapi.dll{#} ^| )
	if not exist "%SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll" (%ch% {02} windowsdefenderapplicationguardcsp.dll{#} ^| ) else (%ch% {0c} windowsdefenderapplicationguardcsp.dll{#} ^| )
	if not exist "%SystemRoot%\System32\wscsvc.dll" (%ch% {02}wscsvc.dll{\n #}) else (%ch% {0c}wscsvc.dll{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealthCore.dll"  (%ch% {02} SecurityHealthCore.dll{\n #}) else (%ch% {0c} SecurityHealthCore.dll{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealthSsoUdk.dll"  (%ch% {02} SecurityHealthSsoUdk.dll{\n #}) else (%ch% {0c} SecurityHealthSsoUdk.dll{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealthUdk.dll" (%ch% {02} SecurityHealthUdk.dll{\n #}) else (%ch% {0c} SecurityHealthUdk.dll{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealthAgent.dll"  (%ch% {02} SecurityHealthAgent.dll{\n #}) else (%ch% {0c} SecurityHealthAgent.dll{\n #})
	pause>nul && cls && goto Start
	
:CreateBackupDefender
	if exist "%SystemDrive%\WDefenderBackup" rd /s /q "%SystemDrive%\WDefenderBackup"
	
rem ������塞 � �᪫�祭�� [� ᠬ�� ��⮤� ���� �஢�ઠ �� ����୮� ����������]
	call :AddExclusion
	
	NSudoLC -U:P -ShowWindowMode:Hide -Wait UnlockerUnpack.bat
	
	Unlocker /unlock "%AllUsersProfile%\Microsoft\Windows Defender" "%SystemDrive%\Program Files\Windows Defender" "%SystemDrive%\Program Files (x86)\Windows Defender"
	
	%ch%    {02} ������ १�ࢭ�� ����� ����� �� %AllUsersProfile%{\n #}
(
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender"
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Windows Security Health" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Security Health"
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Storage Health" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Storage Health"
) >nul 2>&1

	timeout /t 2 /nobreak >nul
	
rem ����砥� ����� Windows. �뢮��� ��, �᫨ ����� �� ᪮��஢�����
	for /f "tokens=4 delims=[] " %%v in ('ver') do set "NumberWin=%%v"

rem �஢�ઠ ��᫥ ����஢���� ������� �����, ᪮��஢����� �� ...
	dir /b "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender" | findstr /r "^" >nul && (
	echo >nul
	) || (
	%ch% {04} ����� "%AllUsersProfile%\Microsoft\Windows Defender" ᪮��஢��� �� 㤠����{\n #}
	%ch% {08} ��� ����� Windows - {03}%NumberWin%{\n #}
	%ch% {08} ���஡�� �⪫���� �㭪�� ���� �� �������� ��� ��१���㧨� ��{\n #}
	%ch% {08} �᫨ ������ �訡�� ��⠥��� ��᫥ ������ �������権 - ᮮ��� �� ���{\n #}
	%ch% {08} ��� ������ � ������� ���� ������ ���� �������{\n #}
	pause
	rd /s /q "%SystemDrive%\WDefenderBackup" >nul 2>&1
	cls && goto Start
	)
	
	%ch%    {02} ������ १�ࢭ�� ����� ����� �� %ProgramFiles% � %ProgramFiles(x86)%{\n #}
(
rem ������ ࠧ��� � ॥��� �� ���஬� �㤥� �஢�����, �� १�ࢭ�� ����� ᮧ����. �ॡ���� ��� �ய�᪠ 㤠����� SysApps [������᭮���/AppRep]
	reg add "HKLM\Software\DefenderKiller" /f

    xcopy /s /e /h /y /i "%SystemDrive%\Program Files\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\Program Files\Windows Defender"
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files\Windows Defender Sleep" "%SystemDrive%\WDefenderBackup\Folder\Program Files\Windows Defender Sleep"
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" "%SystemDrive%\WDefenderBackup\Folder\Program Files\Windows Defender Advanced Threat Protection"
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files\Windows Security" "%SystemDrive%\WDefenderBackup\Folder\Program Files\Windows Security"
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files\PCHealthCheck" "%SystemDrive%\WDefenderBackup\Folder\Program Files\PCHealthCheck"
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files\Microsoft Update Health Tools" "%SystemDrive%\WDefenderBackup\Folder\Program Files\Microsoft Update Health Tools"
	
rem ProgramFiles X86	
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files (x86)\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\Program Files (x86)\Windows Defender"
    xcopy /s /e /h /y /i "%SystemDrive%\Program Files (x86)\Windows Defender Advanced Threat Protection" "%SystemDrive%\WDefenderBackup\Folder\Program Files (x86)\Windows Defender Advanced Threat Protection"
		
) >nul 2>&1

	%ch%    {02} ������ १�ࢭ�� ����� ����� �� System32 � SysWOW64{\n #}
(

rem Windows - System32
    xcopy /s /e /h /y /i "%SystemRoot%\security\database" "%SystemDrive%\WDefenderBackup\Folder\Windows\security\database"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\HealthAttestationClient" "%SystemDrive%\WDefenderBackup\Folder\System32\HealthAttestationClient"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\SecurityHealth" "%SystemDrive%\WDefenderBackup\Folder\System32\SecurityHealth"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\WebThreatDefSvc" "%SystemDrive%\WDefenderBackup\Folder\System32\WebThreatDefSvc"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\Sgrm" "%SystemDrive%\WDefenderBackup\Folder\System32\Sgrm"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\WindowsPowerShell\v1.0\Modules\Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%SystemDrive%\WDefenderBackup\Folder\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\drivers\wd" "%SystemDrive%\WDefenderBackup\Folder\System32\drivers\wd"

rem ����� ���⭨��
	xcopy /s /e /h /y /i "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\Tasks\Microsoft\Windows\Windows Defender"

rem SysWOW64
    xcopy /s /e /h /y /i "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender" "%SystemDrive%\WDefenderBackup\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%SystemDrive%\WDefenderBackup\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	
) >nul 2>&1

	%ch%    {02} ������ १�ࢭ�� ����� 䠩��� �� System32 � SysWOW64{\n #}

(
	md "%SystemDrive%\WDefenderBackup\Files"
	md "%SystemDrive%\WDefenderBackup\Files\System32"
	md "%SystemDrive%\WDefenderBackup\Files\SysWOW64"
	md "%SystemDrive%\WDefenderBackup\Files\Windows\Containers"
	md "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\serviced"
	
rem ����஢���� 䠩��� �� System32
	copy /Y "%SystemRoot%\System32\SecurityHealthService.exe" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthSystray.exe" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthHost.exe" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthAgent.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthSSO.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthProxyStub.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\LogFiles\WMI\RtBackup\EtwRTDefenderApiLogger.etl" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\LogFiles\WMI\RtBackup\EtwRTDefenderAuditLogger.etl" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\smartscreen.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\wscisvif.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\wscproxystub.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\smartscreenps.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\wscapi.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\wscsvc.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthCore.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthSsoUdk.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\SecurityHealthUdk.dll" "%SystemDrive%\WDefenderBackup\Files\System32\"
	copy /Y "%SystemRoot%\System32\smartscreen.exe" "%SystemDrive%\WDefenderBackup\Files\System32\"

rem ����஢���� 䠩��� �� SysWow64
	copy /Y "%SystemRoot%\SysWOW64\smartscreen.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\wscisvif.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\wscproxystub.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\smartscreenps.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\wscapi.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\windowsdefenderapplicationguardcsp.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
		
	copy /Y "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\"
	copy /Y "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\serviced"
	
) >nul 2>&1
	
	%ch%    {02} ������ १�ࢭ�� ����� ����� �� WinSxS{\n #}
(
	md "%SystemDrive%\WDefenderBackup\Folder\WinSxS"
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-defender*") do xcopy "%%i" "%SystemDrive%\WDefenderBackup\Folder\WinSxS\%%~nxi" /I /E /H /Y
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-senseclient-service*") do xcopy "%%i" "%SystemDrive%\WDefenderBackup\Folder\WinSxS\%%~nxi" /I /E /H /Y
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-dynamic-image*") do xcopy "%%i" "%SystemDrive%\WDefenderBackup\Folder\WinSxS\%%~nxi" /I /E /H /Y
) >nul 2>&1

	md "%SystemDrive%\WDefenderBackup\ServicesDrivers"
	md "%SystemDrive%\WDefenderBackup\RegEdit"
	set "PathServDrive=%SystemDrive%\WDefenderBackup\ServicesDrivers"
	set "PathRegedit=%SystemDrive%\WDefenderBackup\RegEdit"
(	
rem ��㦡�
	reg export "HKLM\System\CurrentControlSet\Services\EventLog\System\WinDefend" "%PathServDrive%\WinDefendEvent.reg"
	reg export "HKLM\System\CurrentControlSet\Services\SecurityHealthService" "%PathServDrive%\SecurityHealthService.reg"
	reg export "HKLM\System\CurrentControlSet\Services\Sense" "%PathServDrive%\Sense.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WdNisSvc" "%PathServDrive%\WdNisSvc.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WinDefend" "%PathServDrive%\WinDefend.reg"
	reg export "HKLM\System\CurrentControlSet\Services\wscsvc" "%PathServDrive%\wscsvc.reg"
	reg export "HKLM\System\CurrentControlSet\Services\SgrmBroker" "%PathServDrive%\SgrmBroker.reg"
	reg export "HKLM\System\CurrentControlSet\Services\webthreatdefsvc" "%PathServDrive%\webthreatdefsvc.reg"
	reg export "HKLM\System\CurrentControlSet\Services\webthreatdefusersvc" "%PathServDrive%\webthreatdefusersvc.reg"
	
rem �ࠩ���
	reg export "HKLM\System\CurrentControlSet\Services\WdNisDrv" "%PathServDrive%\WdNisDrv.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WdBoot" "%PathServDrive%\WdBoot.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WdFilter" "%PathServDrive%\WdFilter.reg"
	reg export "HKLM\System\CurrentControlSet\Services\SgrmAgent" "%PathServDrive%\SgrmAgent.reg"
	reg export "HKLM\System\CurrentControlSet\Services\wtd" "%PathServDrive%\wtd.reg"
	reg export "HKLM\System\CurrentControlSet\Services\MsSecWfp" "%PathServDrive%\MsSecWfp.reg"
	reg export "HKLM\System\CurrentControlSet\Services\MsSecFlt" "%PathServDrive%\MsSecFlt.reg"
	reg export "HKLM\System\CurrentControlSet\Services\MsSecCore" "%PathServDrive%\MsSecCore.reg"
	
rem ��ᯮ�� ��⮪ ॥���
	reg export "HKCR\*\shellex\ContextMenuHandlers\EPP" "%PathRegedit%\1.reg"
	reg export "HKCR\Directory\shellex\ContextMenuHandlers\EPP" "%PathRegedit%\2.reg"
	reg export "HKCR\Drive\shellex\ContextMenuHandlers\EPP" "%PathRegedit%\3.reg"
	reg export "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" "%PathRegedit%\4.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" "%PathRegedit%\5.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "%PathRegedit%\6.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "%PathRegedit%\7.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" "%PathRegedit%\8.reg"
	reg export "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" "%PathRegedit%\9.reg"
	reg export "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" "%PathRegedit%\10.reg"
	reg export "HKLM\Software\Microsoft\Windows Defender" "%PathRegedit%\11.reg"
	reg export "HKLM\Software\Microsoft\Windows Defender Security Center" "%PathRegedit%\12.reg"
	reg export "HKLM\Software\Microsoft\Windows Advanced Threat Protection" "%PathRegedit%\13.reg"
	reg export "HKLM\Software\Microsoft\Windows Security Health" "%PathRegedit%\14.reg"
	reg export "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" "%PathRegedit%\15.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" "%PathRegedit%\16.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" "%PathRegedit%\17.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" "%PathRegedit%\18.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" "%PathRegedit%\19.reg"
	reg export "HKCR\CLSID\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" "%PathRegedit%\20.reg"
	
) >nul 2>&1

	%ch%    {08} ����ࢭ�� ����� ᮧ���� � {09}%SystemDrive%\WDefenderBackup{\n #}{\n #}
	exit /b