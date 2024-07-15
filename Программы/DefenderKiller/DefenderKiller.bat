:: DefenderKiller by Vlado - удаление и восстановление Windows Defender [Защитника Windows]
:: За помощь, тесты и многое другое спасибо моему другу Eject - https://win10tweaker.ru/forum/profile/eject
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
rem Проверяем, чтобы в пути не было скобок или восклицательного знака, повышаем права до администратора текущий файл
	if not exist "%~dp0Work" echo Не найдена рабочая папка Work рядом с программой, будет выполнен выход. && timeout /t 7 >nul && exit
	echo "%~dp0" | findstr /r "[()!]" >nul && echo Путь до .bat содержит недопустимые символы, исправьте путь и запустите программу повторно. && timeout /t 7 >nul && exit
	SetLocal EnableDelayedExpansion
	cd /d "%~dp0Work"
	reg query "HKU\S-1-5-19" >nul 2>&1 || nircmd elevate "%~f0" && exit

rem Перезапуск от TrustedInstaller
	if /i "%USERNAME%" neq "%COMPUTERNAME%$" NSudoLC -U:T -P:E -UseCurrentConsole %0 && exit

rem Set variable's
	set "ch=cecho.exe"
	set "AlreadyInExclusion="
	set "ArgNsudo="
	set "LGPOtemp=LGPO-temp.txt"
	set "DefenderKey=HKLM\Software\Policies\Microsoft\Windows Defender"

rem Версия и дата программы
	set Version=12.2.1
	set DateProgram= 09.07.24
	
rem Первое число - ширина, второе - длина
	Mode 80,45
	nircmd win center process cmd.exe & nircmd win settext foreground "DK | v. %Version% | %DateProgram% | By Vlado"
	
rem Удаляем ненужные файлы
	if exist "%SystemDrive%\latestVersion.bat" del /q "%SystemDrive%\latestVersion.bat"
	if exist 7z.exe del /q 7z.exe
	if exist ToolsForDK.zip del /q ToolsForDK.zip

rem Проверка nhmb.exe, ToolsForDK
	if not exist nhmb.exe %ch% {0c} Нет файла nhmb.exe в папке Work.{\n} Перекачайте полный архив DefenderKiller.{\n #}&& timeout /t 5 >nul && exit
	if not exist UnlockerUnpack.bat %ch% {0c} Нет файла UnlockerUnpack.bat в папке Work.{\n} Перекачайте полный архив DefenderKiller.{\n #}&& timeout /t 5 >nul && exit
	
rem Аргумент для NSUDO в зависимости от состояния UAC [C - если отключён / E - если включён]
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" | find /i "0x0" >nul 2>&1 && set "ArgNsudo=C" || set "ArgNsudo=E"
	if not exist "%SystemRoot%\System32\smartscreen.exe" (set "SmartScreen=0a") else (set "SmartScreen=0c")
	if not exist "%SystemRoot%\System32\gpedit.msc" set "NoGP=Yes"

rem Процессы / Службы и Драйвера
	for %%p in (MsMpEng SgrmBroker uhssvc NisSrv MpCmdRun MPSigStub SecHealthUI SecurityHealthSystray SecurityHealthService SecurityHealthHost MpDefenderCoreService) do (
	qprocess "%%~p.exe" >nul 2>&1 && set "%%~p=0c" || set "%%~p=0a")
	for %%x in (WinDefend WdNisSvc Sense wscsvc SgrmBroker SecurityHealthService webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent wtd MsSecWfp MsSecFlt MsSecCore) do sc query "%%~x" >nul 2>&1 && set "%%~x=0c" || set "%%~x=0a"

rem Путь к папке задач планировщика
	set PathTask=%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender
	if not exist "%PathTask%\Windows Defender Cache Maintenance" (set "Maintenance=0a") else (set "Maintenance=0c")
	if not exist "%PathTask%\Windows Defender Scheduled Scan" (set "Scan=0a") else (set "Scan=0c")
	if not exist "%PathTask%\Windows Defender Verification" (set "Verification=0a") else (set "Verification=0c")
	if not exist "%PathTask%\Windows Defender Cleanup" (set "Cleanup=0a") else (set "Cleanup=0c")
	if not exist "%SystemRoot%\System32\Tasks\Microsoft\Windows\AppID\SmartScreenSpecific" (set "SmartScreenSpecific=0a") else (set "SmartScreenSpecific=0c")

rem Начало меню программы после всех проверок
	%ch% {09}Состояние процессов защитника:{\n #}
	%ch% {%SmartScreen%} SmartScreen {08}[Windows Defender SmartScreen]{\n #}
	%ch% {%MsMpEng%} MsMpEng    {08} [Antimalware Service Executable]{\n #}
	%ch% {%SgrmBroker%} SgrmBroker  {08}[Брокер среды выполнения System Guard]{\n #}
	%ch% {%uhssvc%} uhssvc     {08} [Microsoft Update Health Service]{\n #}
	%ch% {%NisSrv%} NisSrv     {08} [Network Realtime Inspection]{\n #}
	%ch% {%MpCmdRun%} MpCmdRun   {08} [Microsoft malware protection]{\n #}
	%ch% {%MPSigStub%} MPSigStub{08}   [Malware Protection Signature Update Stub]{\n #}
	%ch% {%SecHealthUI%} SHealthUI{08}   [Окно Безопасность Windows]{\n #}
	%ch% {%SecurityHealthSystray%} HealthTray{08}  [Иконка Безопасности в трее]{\n #}
	%ch% {%SecurityHealthService%} HealthServ{08}  [SecurityHealthService]{\n #}
	%ch% {%SecurityHealthHost%} HealthHost{08}  [SecurityHealthHost]{\n #}
	%ch% {%MpDefenderCoreService%} CoreService{#}{08} [Antimalware Core Service]{\n #}{\n #}

	%ch% {09}Состояние служб и драйверов защитника:{\n #}
rem 	Службы
	%ch% {%WinDefend%} WinDefend  {08} [Служба Антивирусная программа Защитника Windows]{\n #}
	%ch% {%WdNisSvc%} WdNisSvc {08}   [Служба проверки сети Windows Defender Antivirus]{\n #}
	%ch% {%Sense%} Sense      {08} [Служба Advanced Threat Protection]{\n #}
	%ch% {%wscsvc%} wscsvc      {08}[Служба Центр обеспечения безопасности]{\n #}
	%ch% {%SgrmBroker%} SgrmBroker  {08}[Служба Брокер мониторинга среды выполнения System Guard]{\n #}
	%ch% {%SecurityHealthService%} SHealthSer  {08}[Служба Центр безопасности Защитника Windows]{\n #}
	%ch% {%webthreatdefsvc%} webthreat   {08}[Служба защиты от Веб-угроз - webthreatdefsvc]{\n #}
	%ch% {%webthreatdefusersvc%} webthreatu  {08}[Служба защиты пользоват. от Веб-угроз - webthreatdefusersvc]{\n #}
rem 	Драйверы
	%ch% {%WdNisDrv%} WdNisDrv    {08}[Драйвер WD Network Inspection Driver]{\n #}
	%ch% {%WdBoot%} WdBoot      {08}[Драйвер WD Antivirus Boot Driver]{\n #}
	%ch% {%WdFilter%} WdFilter{#}{08}    [Драйвер WD Antivirus Mini-Filter Driver]{\n #}
	%ch% {%SgrmAgent%} SgrmAgent{#}{08}   [Драйвер System Guard Runtime Monitor Agent Driver]{\n #}
	%ch% {%wtd%} wtd{#}{08}         [Драйвер WTD Driver]{\n #}
	%ch% {%MsSecWfp%} MsSecWfp{#}{08}    [Драйвер Microsoft Security WFP Callout Driver]{\n #}
	%ch% {%MsSecFlt%} MsSecFlt{#}{08}    [Драйвер Security Events Component Minifilter]{\n #}
	%ch% {%MsSecCore%} MsSecCore{#}{08}   [Драйвер Microsoft Security Core Boot Driver]{\n #}
	
	echo.

	%ch% {09}Состояние заданий в планировщике:{\n #}
	%ch% {%Maintenance%} Windows Defender Cache Maintenance{\n #}
	%ch% {%Scan%} Windows Defender Scheduled Scan{\n #}
	%ch% {%Verification%} Windows Defender Verification{\n #}
	%ch% {%Cleanup%} Windows Defender Cleanup{\n #}
	%ch% {%SmartScreenSpecific%} SmartScreenSpecific{\n #}
	
	echo.
	
	%ch% {0f} 1 - {04}Удалить Защитник{\n #}
	%ch% {0f} 2 - {08}Проверить состояние папок и файлов Защитника{\n #}
	%ch% {0f} 3 - {08}Проверить обновления{\n #}
	%ch% {0f} 4 - {0e}Восстановление, удаление Безопасности{\n #}
	
	set "input="
	set /p input=
	if not defined input  cls && goto Start
	if "%input%"=="1"  cls && goto DeleteDefender
	if "%input%"=="2"  cls && goto Catalogs
	if "%input%"=="3"  cls && goto CheckUpdate
	if "%input%"=="4"  cls && goto ManageDefender
	cls & %ch%    {0c}Такой функции не существует{\n #}
	timeout /t 2 >nul && cls && goto Start

:DeleteDefender
rem Проверка разрядности
	set xOS=x64& (if "%processor_architecture%"=="x86" if not defined PROCESSOR_ARCHITEW6432 Set xOS=x86)

rem Свободное место на диске с помощью vbs
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

rem Если существует Windows Defender,
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (
	
rem Проверяем, есть ли резервная копия. Если резервной копии нет - предлагаем создать.
	if not exist "%SystemDrive%\WDefenderBackup" (
		nhmb "Создать резервную копию перед удалением?\nМожно будет восстановить защитник с помощью копии.\n\nВыбирайте нет, только в том случае, если Вы НЕ пользуетесь обновлениями Windows." "CreateBackupWD" "Warning|YesNo|DefButton2"
		if errorlevel 7 goto SkipCreateBackup
		if errorlevel 6 call :CreateBackupDefender)
	
:SkipCreateBackup
rem SmartScreen / Уведомления от центра безопасности. NSudo - для понижения прав, т.к. эта консоль запущена от TI и ветка HKCU для TI.
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nu
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul
	
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >null

rem MSRT - Средство удаления вредоносных программ от Microsoft. [Не отправлять отчёты от MSRT/Отключить получение обновлений для MSRT]
	reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul
	reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul
	)
	
rem Пропуск Unlocker; DefenderStop, если обе папки уже удалены
		if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
    if not exist "%SystemDrive%\Program Files\Windows Defender" (
        goto DefenderAlreadyDeleted
		)
	)

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

rem Добавляем в исключения [в самом методе есть проверка на повторное добавление в исключения]
	call :AddExclusion
	nircmd win settext foreground "DK"

rem Завершаем процессы
	for %%x in (MpCmdRun MpDefenderCoreService MsMpEng SecurityHealthSystray SecurityHealthService SecurityHealthHost smartscreen SgrmBroker SecHealthUI uhssvc NisSrv MPSigStub MSASCuiL MRT) do nircmd killprocess "%%~x"

rem Распаковка Unlocker с помощью .bat Compressed2TXT
	NSudoLC -U:P -ShowWindowMode:Hide -Wait UnlockerUnpack.bat
	
	%ch%    {08} Проводник завершён{\n #}
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait cmd.exe /c taskkill /f /im explorer.exe >nul 2>&1
	%ch%    {0c} Выполняем удаление с помощью Unlocker by Eject{\n #}{\n #}
	Unlocker /DeleteDefender

:CheckFolder
	if exist "%Temp%\IObitUnlocker\IObitUnlocker.exe" goto CheckFolder
	
rem Проверяем после удаления, остались ли папки. Если остались - выполняем повторное удаление с помощью Unlocker
	for %%d in ("%AllUsersProfile%\Microsoft\Windows Security Health", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender") do (
		if exist %%d (
			%ch%    {08} Папка %%d не удалилась{\n #}
			%ch%    {0c} Удаление %%d{\n #}{\n #}
			timeout /t 2 /nobreak >nul
			Unlocker /DeleteDefender
		)
	)
	
rem Запуск проводника
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c start explorer.exe >nul 2>&1
	
rem Применяем основную политику по отключению защитника уже после удаления, если это не HOME версия, где нет оснастки групповых политик.
rem Применение политики - необязательное действие на данном этапе, поскольку защитник удалён. Политика - 'пустышка'. Её наличие необязательно.
rem Требуется только для того, чтобы другой софт, который проверяет состояние защитника по данному параметру считал, что защитник уже отключён
rem Применение данной политики на последних версиях Windows 11, возможно уже и Windows 10 невозможно перед удалением защитника, т.к. Microsoft при применении этой политики моментально замедляет запуск программ и работу ПК.
rem Исследование - https://azuretothemax.net/2023/05/01/murdering-windows-11-performance-by-disabling-windows-defender-what-not-to-do/
	if not defined NoGP (
		call :LGPOFILE reg add "%DefenderKey%" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
		call :LGPO_APPLY >nul 2>&1
		nircmd win activate process cmd.exe
	)

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:DefenderAlreadyDeleted
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" %ch%    {03} Удаляем папки и файлы Защитника{\n #}{\n #}
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
	
rem Удаление файлов System32
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
	
rem Удаление SmartScreen.exe
	taskkill /f /im smartscreen.exe
	ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen.exedel"
	del /f /q "%SystemRoot%\System32\smartscreen.exe"
	del /f /q "%SystemRoot%\System32\smartscreen.exedel"
	
rem Удаление файлов SysWOW64
	del /f /q "%SystemRoot%\SysWOW64\smartscreen.dll"
	del /f /q "%SystemRoot%\SysWOW64\wscisvif.dll"
	del /f /q "%SystemRoot%\SysWOW64\wscproxystub.dll"
	del /f /q "%SystemRoot%\SysWOW64\smartscreenps.dll"
	del /f /q "%SystemRoot%\SysWOW64\wscapi.dll"
	del /f /q "%SystemRoot%\SysWOW64\windowsdefenderapplicationguardcsp.dll"
) >nul 2>&1
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (
	%ch%    {03} Удаляем службы и драйвера{\n #}
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
	%ch%    {03} Удаляем задания из планировщика{\n #}
	%ch%    {0a} Windows Defender Cache Maintenance{\n #}
	%ch%    {0a} Windows Defender Cleanup{\n #}
	%ch%    {0a} Windows Defender Scheduled Scan{\n #}
	%ch%    {0a} Windows Defender Verification{\n #}
	%ch%    {0a} SmartScreenSpecific{\n #}{\n #}
	)

(
rem Удаление задач планировщика
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f
	schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /f
	schtasks /Delete /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /f

rem Удаление ветки Windows Defender из реестра
	reg delete "HKLM\Software\Microsoft\Windows Defender" /f
	reg delete "HKLM\Software\Microsoft\Windows Defender Security Center" /f
	reg delete "HKLM\Software\Microsoft\Windows Advanced Threat Protection" /f
	reg delete "HKLM\Software\Microsoft\Windows Security Health" /f

	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" /f
	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" /f

rem Очистка контекстного меню
	reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" /v "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f

rem Удаление из автозапуска
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /f
	
rem Удаление надписи в параметрах
	reg delete "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" /f
	
rem Удаление журналов событий
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" /f

rem Удаление из Панели управления элемента Windows Defender [Windows 8.1]
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	reg delete "HKCR\CLSID\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	
) >nul 2>&1

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

rem Если удалялась эта ветка ранее, пропускаем удаление папок из WinSxS
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" >nul 2>&1 && (
rem Проверяем создавался ли бэкап, если нет - спрашиваем точно ли удалить папки из WinSxS
	reg query "HKLM\Software\DefenderKiller" >nul 2>&1 && (
		echo >nul
	) || (
		nhmb "Вы не создали резервную копию.\n\nУдаление папок в WinSxS может нарушить установку некоторых обновлений Windows!\n\nУдалить папки Windows Defender из WinSxS?" "DK" "Warning|YesNo|DefButton2"
	if errorlevel 7 (
		%ch%    {0e} Вы пропустили удаление папок из WinSxS{\n #}
		%ch%    {08} Этот вопрос появится при следующем удалении{\n #}{\n #}
		goto FinishDelete)
	if errorlevel 6 echo >nul
	)
	
	%ch%    {03} Удаляем папки из WinSxS{\n #}{\n #}
	for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*windows-defender*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*windows-senseclient-service*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*windows-dynamic-image*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	)

rem Удаление ветки после удаления папок из WinSxS. Выполняется СТРОГО после удаления папок из WinSxS, чтобы удаление было всего 1 раз.
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /f >nul 2>&1
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:FinishDelete
rem Освобождённое место на диске
	for /f %%i in ('cscript //nologo temp.vbs') do set sFreeSize1=%%i
	set /a CountFreeSize=%sFreeSize1% - %sFreeSize%
	if defined CountFreeSize %ch%    {0c} %CountFreeSize% MB {0f}освобождено на диске %SystemDrive%\ после удаления{\n #}
	
rem Удаляем Unlocker, его драйвер и остальные файлы. Драйвер восстановится сам, если используется установочный IObitUnlocker
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
			%ch%    {08} Ориентируйтесь на состояние папок {0f}- цифра 2{\n #}
			%ch%    {08} Зеленым - удалено. Красным - не удалено.{\n #}
			%ch%    {0e} Если что-то не удалилось - перезагрузите ПК и повторите процесс удаления.{\n #}{\n #}
			reg query "HKLM\System\CurrentControlset\Services\WinDefend" >nul 2>&1 && %ch%    {04} Все службы Защитника не удалены.{\n #}{08}    Повторите удаление после перезагрузки ПК.{\n #}{\n #}
			%ch%    {08} Нажмите любую клавишу для возврата в главное меню.{\n #}
			pause>nul && cls && goto Start
		)
	)
	
	echo.
	nhmb "Защитник Windows не удалён.\nЕсли появляется это сообщение несколько раз, выполните перезагрузку компьютера и повторите попытку удаления.\n\nПовторить удаление защитника?\n" "DK" "Information|YesNo"
	if errorlevel 7 cls && goto Start
	if errorlevel 6 cls && set "AlreadyInExclusion=Yes" && goto DeleteDefender
			
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:ManageDefender
	%ch% {\n #}{08} 1{#} - Восстановить защитник из копии{\n #}
	%ch% {08} 2{#} - Применить/Откатить групповые политики{\n #}
	%ch% {08} 3{#} - Удалить приложение Безопасность [значок в пуске] [с подтверждением]{\n #}
	echo.
	%ch% {0e} [Enter]{#} - {08}Вернуться в главное меню{\n #}
	set "input="
	set /p input=
	if not defined input	  cls && goto Start
	if "%input%"=="1"    goto RestoreDefender
	if "%input%"=="2"    goto GroupPolicyWD
	if "%input%"=="3"    goto SecHealthUI
	cls && goto ManageDefender

:RestoreDefender
rem Для корректного отображения диалогового окна, т.к. программа запущена от TI
	if not exist "%SystemRoot%\System32\config\systemprofile\Desktop" md "%SystemRoot%\System32\config\systemprofile\Desktop"
	
	%ch% {0c} Убедитесь, что выбранная рез. копия была создана на этой же версии Windows{\n #}
	
	set "BackupFolder="
	for /f %%a in ('powershell -c "(New-Object -COM 'Shell.Application').BrowseForFolder(0, 'Выберите папку WDefenderBackup с ранее созданной резервной копией Windows Defender. После выбора папки будет задан вопрос о восстановлении защитника.', 0, 0).Self.Path"') do set "BackupFolder=%%a"
	echo.
	if not defined BackupFolder cls && goto ManageDefender
	if not exist "%BackupFolder%\Folder" %ch%    {04} Неверная резервная копия. Выберите правильную резервную копию.{\n #}&&timeout /t 3 >nul && cls && goto ManageDefender
	if not exist "%BackupFolder%\ServicesDrivers" %ch%    {04} Неверная резервная копия. Выберите правильную резервную копию.{\n #}&&timeout /t 3 >nul && cls && goto ManageDefender
	
	%ch% {03} Восстановление защитника{\n #}{\n #}
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

rem Восстановление реестра/служб, драйверов
	for %%f in ("RegEdit\*.reg") do reg import "%%f"
	for %%f in ("ServicesDrivers\*.reg") do reg import "%%f"

rem Восстановление SmartScreen.exe
	if exist "%SystemRoot%\System32\smartscreen_disabled.exe" rename "%SystemRoot%\System32\smartscreen_disabled.exe" "smartscreen.exe"

rem Удаляем раздел по которому проверяется создана ли резервная копия. Теперь SysApps будут удаляться.
	reg delete "HKLM\Software\DefenderKiller" /f

rem Очищаем все добавленные ранее пути в исключения защитника
	reg delete "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" /f
	
rem Восстановление параметров реестра
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /f
	reg delete "HKLM\Software\Policies\Microsoft\MRT" /f
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f
) >nul 2>&1

	popd
	
	call :RestoreGP
	timeout /t 1 /nobreak >nul
	call :RestoreGP
	nhmb "Требуется перезапуск ПК" "DK" "Information|Ok"
	cls && goto Start

:GroupPolicyWD
	if not exist "%SystemRoot%\System32\gpedit.msc" %ch%  {04} Не Найдено ГП, у Вас HOME версия, либо какая-то сборка.{\n #}&&timeout /t 3 >nul && cls && goto ManageDefender
	%ch% {\n #}{0f} 1{#} - {0f}Применить групповые политики защитника{\n #}
	%ch% {0f} 2{#} - {0f}Откатить групповые политики защитника{\n #}
	%ch% {0f} 3{#} - {08}Отменить выбор{\n #}
	
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
rem Восстановление политик
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
	ver | findstr /c:"6.3" /c:"6.2" /c:"6.1" >nul && %ch%    {04} Не требуется на данной версии Windows{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender

rem Получаем SID
	set "SID="
	for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoLogonSID" 2^>nul') do set "SID=%%a"
	if not defined SID for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v "LastLoggedOnUserSID" 2^>nul') do set "SID=%%a"
	if not defined SID %ch%    {04} SID не был получен, отмена удаления приложений{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender
	
	%ch% {\n} После удаления приложения зайти в настройки защитника будет {04}невозможно.{\n #}
	%ch% {08} 1.{#} {0c}Удалить приложения{\n #}
	%ch% {08} 2.{#} {08}Отмена{\n #}
	choice /c 12 /n /m " "
	if errorlevel 2 cls && goto ManageDefender
	
rem Получаем имя SystemApp Безопасность Windows [SecHealthUI] - Оснастка для управления антивирусной программой Windows Defender
	%ch%    {03} Удаляем Безопасность Windows{\n #}
	set "NameSecHealth="
	for /F "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*SecHealthUI*" /k^|findstr ^H`) do set NameSecHealth=%%~nxn
	if not defined NameSecHealth %ch%    {02} Приложение Безопасность Windows удалено{\n #}{\n #}&& goto AppRepSys

	%ch% {08} %NameSecHealth%{\n #}{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameSecHealth%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameSecHealth%" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *SecHealthUI* | Remove-AppxPackage"
	NSudoLC -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *SecHealthUI* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*SecHealthUI*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem Эти папки можно удалять. Восстанавливаются сами, если восстановить приложение Безопасность.
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"

:AppRepSys
rem Получаем имя SystemApp AppRep [SmartScreen]
	%ch%    {03} Удаляем SmartScreen защитника Windows{\n #}
	set "NameAppRep="
	for /F "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do set NameAppRep=%%~nxn
	if not defined NameAppRep %ch%    {02} Приложение SmartScreen защитника Windows удалено{\n #}&& pause && cls && goto ManageDefender

	%ch% {08} %NameAppRep%{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameAppRep%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameAppRep%" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *Apprep.ChxApp* | Remove-AppxPackage"
	NSudoLC -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *Apprep.ChxApp* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem Эти папки можно удалять, восстанавливаются сами, если восстановить приложение Apprep.ChxApp
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	
	pause && cls && goto ManageDefender

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:AddExclusion
	if defined AlreadyInExclusion (
	%ch%    {08} Пропуск добавления в исключения Защитника [уже добавлено]{\n #}{\n #}
	exit /b)
	%ch%    {03} Добавляем в исключения Защитника{\n #}{\n #}
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-PSDrive -PSProvider 'FileSystem' | ForEach-Object { Add-MpPreference -ExclusionPath $_.Root }" >nul 2>&1
	set "AlreadyInExclusion=Yes"
	timeout /t 2 /nobreak >nul
	exit /b
		
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

rem Создано WestLife/AutoSettings - https://disk.yandex.ru/d/CMqvcp1F3QiaWL
:LGPOFILE
	setlocal
	if /i "%~2" NEQ "delete" if /i "%~2" NEQ "add" (
	 %ch%     {0c}Пропуск добавления параметра в LGPO файл, неправильная команда{#}:{\n #} & %ch%    %1 {0e}%2{#} %3 {\n #} & exit /b)
	 
	if /i "%~2" EQU "delete" if "%~7" NEQ "" (
	 %ch%     {0c}Пропуск добавления параметра в LGPO файл, ошибка в параметре{#}:{\n #} & echo.   %1 %2 %3 & %ch%        %4 %5 %6 {0e}%7 %8 %9 {\n #}& exit /b)
	 
	set "RegType=%~7:"
	set "RegType=%RegType:REG=%"
	set "RegType=%RegType:_=%"
	set "RegType=%RegType:PAND=%"
	if "%~3" NEQ "" for /f "tokens=1* delims=\" %%I in ("%~3") do ( set "RegKey=%%J"
	 if /i "%%I" EQU "HKEY_LOCAL_MACHINE" (set Config=Computer) else if /i "%%I" EQU "HKLM" (set Config=Computer
	 ) else if /i "%%I" EQU "HKEY_CURRENT_USER" (set Config=User) else if /i "%%I" EQU "HKCU" (set Config=User
	 ) else (%ch%     {0c}Пропуск добавления параметра в LGPO файл, неверный раздел{#}: {0e}"%%I"{\n #} & %ch%    %1 %2 %3 {\n #} & exit /b))
	 
	if "%~9" NEQ "" set "Action=%RegType%%~9"
	if /i "%~6" EQU "/d" set "Action=SZ:%~7"
	if /i "%~2" EQU "delete" set "Action=DELETE"
	if "%~5" EQU "" ( set "Action=DELETEALLVALUES" & set "ValueName=*" ) else ( set "ValueName=%~5" )
	if /i "%~2" EQU "add" if /i "%~4" EQU "/f" set "Action=CREATEKEY" & set "ValueName=*"
	(echo.%Config%& echo.%RegKey%& echo.%ValueName%& echo.%Action%& echo.)>>"%LGPOtemp%"
	exit /b

:LGPO_APPLY
	taskkill /f /im mmc.exe >nul 2>&1
	%ch% {04} Применение ГП{\n #}{\n #}&LGPO.exe /t "%LGPOtemp%" /q
	if exist "%LGPOtemp%" del /f /q "%LGPOtemp%"
	exit /b
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:CheckUpdate
rem Проверка наличия curl в папке Work или в папке System32 для проверки обновлений
		if not exist "%SystemRoot%\System32\curl.exe" (
	if not exist "%~dp0Work\curl.exe" (
	%ch% {04} Программа curl не найдена в папке Work и в папке System32.{\n #}
	%ch% {04} Поместите программу в папку System32 или в Work{\n #}
	%ch% {08} Скачать можно тут - https://curl.se/windows/{\n #}
	pause && exit))
	
rem Проверяем наличие интернет-соединения
	ping pastebin.com -n 1 -w 1000 |>nul find /i "TTL="|| cls && %ch% {04} Ошибка проверки, нет интернет-соединения.{\n #}&&timeout /t 3 >nul && cls && goto Start

rem Проверка обновлений программы
	curl -g -k -L -# -o "%SystemDrive%\latestVersion.bat" "https://pastebin.com/raw/dnENFgmC" >nul 2>&1
	call "%SystemDrive%\latestVersion.bat"
	if "%Version%" lss "%latestVersion%" (cls) else (
	cls
	%ch% {0a} Обновлений не найдено. У Вас актуальная версия {0f}- {0e}%Version%{\n #}{\n #}
	%ch% {08} Для возврата в главное меню нажмите любую клавишу.{\n #}
	pause >nul
	goto Start)

rem Обновление программы
	%ch%  {0f} Найдена новая версия, нажмите любую клавишу чтобы обновить программу{\n #}
	pause>nul
	curl -g -k -L -# -o %0 "https://github.com/oatmealcookiec/MyProgramm/releases/latest/download/DefenderKiller.bat" >nul 2>&1
	call %0
	cls && exit
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:Catalogs
	%ch% {03}Основные 2 папки{\n #}
	if not exist "%SystemDrive%\Program Files\Windows Defender" (%ch% {02} %SystemDrive%\Program Files\Windows Defender {08}- основная папка защитника 1{\n #}) else (%ch% {04} %SystemDrive%\Program Files\Windows Defender{08} - основная папка защитника 1{\n #})
	if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (%ch% {02} %AllUsersProfile%\Microsoft\Windows Defender {08}- основная папка защитника 2{\n #}) else (%ch% {04} %AllUsersProfile%\Microsoft\Windows Defender{08} - основная папка защитника 2{\n #})
	echo.
	%ch% {09}Папки в %SystemRoot%\System32{\n #}
rem 14.03.23
	if not exist "%SystemRoot%\System32\HealthAttestationClient" (%ch% {0a} %SystemRoot%\System32\HealthAttestationClient{\n #}) else (%ch%  {0c}%SystemRoot%\System32\HealthAttestationClient{\n #})
	if not exist "%SystemRoot%\System32\SecurityHealth" (%ch% {0a} %SystemRoot%\System32\SecurityHealth{\n #}) else (%ch%  {0c}%SystemRoot%\System32\SecurityHealth{\n #})
	if not exist "%SystemRoot%\System32\WebThreatDefSvc" (%ch% {0a} %SystemRoot%\System32\WebThreatDefSvc{\n #}) else (%ch%  {0c}%SystemRoot%\System32\WebThreatDefSvc{\n #})
	if not exist "%SystemRoot%\System32\Sgrm" (%ch% {0a} %SystemRoot%\System32\Sgrm{\n #}) else (%ch%  {0c}%SystemRoot%\System32\Sgrm{\n #})
	if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" (%ch% {0a} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender{\n #}) else (%ch%  {0c}%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender{\n #})
	if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" (%ch% {0a} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance{\n #}) else (%ch%  {0c}%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance{\n #})
	if not exist "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" (%ch% {0a} %SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender{\n #}) else (%ch%  {0c}%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender{\n #})
	echo.
	%ch% {09}Папки в C:\Program Files{\n #}
	if not exist "%SystemDrive%\Program Files\Windows Defender Sleep" (%ch% {0a} C:\Program Files\Windows Defender Sleep {\n #}) else (%ch%  {4f}C:\Program Files\Windows Defender Sleep{\n #})
	if not exist "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" (%ch% {0a} C:\Program Files\Windows Defender Advanced Threat Protection{\n #}) else (%ch%  {0c}C:\Program Files\Windows Defender Advanced Threat Protection{\n #})
	if not exist "%SystemDrive%\Program Files\Windows Security" (%ch% {0a} C:\Program Files\Windows Security{\n #}) else (%ch%  {0c}C:\Program Files\Windows Security{\n #})
	if not exist "%SystemDrive%\Program Files\PCHealthCheck" (%ch% {0a} C:\Program Files\PCHealthCheck{\n #}) else (%ch%  {0c}C:\Program Files\PCHealthCheck{\n #})
	if not exist "%SystemDrive%\Program Files\Microsoft Update Health Tools" (%ch% {0a} C:\Program Files\Microsoft Update Health Tools{\n #}) else (%ch%  {0c}C:\Program Files\Microsoft Update Health Tools{\n #})
	echo.
	%ch% {09}Папки в C:\Program Files (^x86^){\n #}
	if not exist "%ProgramFiles(x86)%\Windows Defender" (%ch% {0a} C:\Program Files (^x86^)\Windows Defender{\n #}) else (%ch%  {0c}C:\Program Files (^x86^)\Windows Defender{\n #})
	if not exist "%ProgramFiles(x86)%\Windows Defender Advanced Threat Protection" (%ch% {0a} C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection{\n #}) else (%ch%  {0c}C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection{\n #})
	echo.
	%ch% {09}Папки в C:\ProgramData{\n #}
	if not exist "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" (%ch% {0a} C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection{\n #}) else (%ch%  {0c}C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection{\n #})
	if not exist "%AllUsersProfile%\Microsoft\Windows Security Health" (%ch% {0a} C:\ProgramData\Microsoft\Windows Security Health{\n #}) else (%ch%  {0c}C:\ProgramData\Microsoft\Windows Security Health{\n #})
	if not exist "%AllUsersProfile%\Microsoft\Storage Health" (%ch% {0a} C:\ProgramData\Microsoft\Storage Health{\n #}) else (%ch%  {0c}C:\ProgramData\Microsoft\Storage Health{\n #})
	echo.
	%ch% {09}Папка задач планировщика защитника{\n #}
	if not exist "%SYSTEMROOT%\System32\Tasks\Microsoft\Windows\Windows Defender" (%ch% {0a} C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender{\n #}) else (%ch%  {0c}C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender{\n #})
	echo.		
	%ch% {09}Остальные файлы{\n #}
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
	
rem Добавляем в исключения [в самом методе есть проверка на повторное добавление]
	call :AddExclusion
	
	NSudoLC -U:P -ShowWindowMode:Hide -Wait UnlockerUnpack.bat
	
	Unlocker /unlock "%AllUsersProfile%\Microsoft\Windows Defender" "%SystemDrive%\Program Files\Windows Defender" "%SystemDrive%\Program Files (x86)\Windows Defender"
	
	%ch%    {02} Создаём резервную копию папок из %AllUsersProfile%{\n #}
(
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender"
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Windows Security Health" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Security Health"
    xcopy /s /e /h /y /i "%AllUsersProfile%\Microsoft\Storage Health" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Storage Health"
) >nul 2>&1

	timeout /t 2 /nobreak >nul
	
rem Получаем версию Windows. Выводим её, если папка не скопировалась
	for /f "tokens=4 delims=[] " %%v in ('ver') do set "NumberWin=%%v"

rem Проверка после копирования главной папки, скопировалась ли ...
	dir /b "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender" | findstr /r "^" >nul && (
	echo >nul
	) || (
	%ch% {04} Папку "%AllUsersProfile%\Microsoft\Windows Defender" скопировать не удалось{\n #}
	%ch% {08} Ваша версия Windows - {03}%NumberWin%{\n #}
	%ch% {08} Попробуйте отключить функцию защита от подделки или перезагрузите ПК{\n #}
	%ch% {08} Если данная ошибка остается после данных манипуляций - сообщите на форум{\n #}
	%ch% {08} Для возврата в главное меню нажмите любую клавишу{\n #}
	pause
	rd /s /q "%SystemDrive%\WDefenderBackup" >nul 2>&1
	cls && goto Start
	)
	
	%ch%    {02} Создаём резервную копию папок из %ProgramFiles% и %ProgramFiles(x86)%{\n #}
(
rem Создаём раздел в реестре по которому будем проверять, что резервная копия создана. Требуется для пропуска удаления SysApps [Безопасность/AppRep]
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

	%ch%    {02} Создаём резервную копию папок из System32 и SysWOW64{\n #}
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

rem Задачи защитника
	xcopy /s /e /h /y /i "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\Tasks\Microsoft\Windows\Windows Defender"

rem SysWOW64
    xcopy /s /e /h /y /i "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender" "%SystemDrive%\WDefenderBackup\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%SystemDrive%\WDefenderBackup\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	
) >nul 2>&1

	%ch%    {02} Создаём резервную копию файлов из System32 и SysWOW64{\n #}

(
	md "%SystemDrive%\WDefenderBackup\Files"
	md "%SystemDrive%\WDefenderBackup\Files\System32"
	md "%SystemDrive%\WDefenderBackup\Files\SysWOW64"
	md "%SystemDrive%\WDefenderBackup\Files\Windows\Containers"
	md "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\serviced"
	
rem Копирование файлов из System32
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

rem Копирование файлов из SysWow64
	copy /Y "%SystemRoot%\SysWOW64\smartscreen.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\wscisvif.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\wscproxystub.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\smartscreenps.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\wscapi.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
	copy /Y "%SystemRoot%\SysWOW64\windowsdefenderapplicationguardcsp.dll" "%SystemDrive%\WDefenderBackup\Files\SysWow64\"
		
	copy /Y "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\"
	copy /Y "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\serviced"
	
) >nul 2>&1
	
	%ch%    {02} Создаём резервную копию папок из WinSxS{\n #}
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
rem Службы
	reg export "HKLM\System\CurrentControlSet\Services\EventLog\System\WinDefend" "%PathServDrive%\WinDefendEvent.reg"
	reg export "HKLM\System\CurrentControlSet\Services\SecurityHealthService" "%PathServDrive%\SecurityHealthService.reg"
	reg export "HKLM\System\CurrentControlSet\Services\Sense" "%PathServDrive%\Sense.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WdNisSvc" "%PathServDrive%\WdNisSvc.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WinDefend" "%PathServDrive%\WinDefend.reg"
	reg export "HKLM\System\CurrentControlSet\Services\wscsvc" "%PathServDrive%\wscsvc.reg"
	reg export "HKLM\System\CurrentControlSet\Services\SgrmBroker" "%PathServDrive%\SgrmBroker.reg"
	reg export "HKLM\System\CurrentControlSet\Services\webthreatdefsvc" "%PathServDrive%\webthreatdefsvc.reg"
	reg export "HKLM\System\CurrentControlSet\Services\webthreatdefusersvc" "%PathServDrive%\webthreatdefusersvc.reg"
	
rem Драйвера
	reg export "HKLM\System\CurrentControlSet\Services\WdNisDrv" "%PathServDrive%\WdNisDrv.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WdBoot" "%PathServDrive%\WdBoot.reg"
	reg export "HKLM\System\CurrentControlSet\Services\WdFilter" "%PathServDrive%\WdFilter.reg"
	reg export "HKLM\System\CurrentControlSet\Services\SgrmAgent" "%PathServDrive%\SgrmAgent.reg"
	reg export "HKLM\System\CurrentControlSet\Services\wtd" "%PathServDrive%\wtd.reg"
	reg export "HKLM\System\CurrentControlSet\Services\MsSecWfp" "%PathServDrive%\MsSecWfp.reg"
	reg export "HKLM\System\CurrentControlSet\Services\MsSecFlt" "%PathServDrive%\MsSecFlt.reg"
	reg export "HKLM\System\CurrentControlSet\Services\MsSecCore" "%PathServDrive%\MsSecCore.reg"
	
rem Экспорт веток реестра
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

	%ch%    {08} Резервная копия создана в {09}%SystemDrive%\WDefenderBackup{\n #}{\n #}
	exit /b