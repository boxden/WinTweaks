::::::: DK by Vlado - удаление и восстановление Windows Defender. https://win10tweaker.ru/forum/topic/defenderkiller | https://github.com/oatmealcookiec/DK

::::::: Unlocker by Eject https://win10tweaker.ru/forum/topic/unlocker :::::::
::::::: NSudo https://github.com/M2TeamArchived/NSudo/releases :::::::
::::::: 7Z https://www.7-zip.org/ :::::::

:Start
	cls
	@echo off
	Title DK
	chcp 65001 >nul
	Color 0f
	SetLocal EnableDelayedExpansion	
	
	if not exist "%~dp0Work" echo  Нет папки Work рядом. Будет выполнен выход. && timeout /t 7 >nul && exit
	echo "%~dp0" | findstr /r "[()!]" >nul && echo  Путь до bat содержит недопустимые символы. Будет выполнен выход. && timeout /t 7 >nul && exit
	
	set "ch=cecho.exe"
	cd /d "%~dp0Work"
	call :NullVar NeedFiles Arch Version DateProgram NumberWin

rem Список нужных файлов для работы DK
	set NeedFiles=7z.exe cecho.exe DKT.zip nircmd.exe NSudoLG.exe
	for %%f in (%NeedFiles%) do if not exist %%f echo  Нет файла %%f в папке Work. && echo. Перекачайте полный архив DK. && timeout /t 5 >nul && exit
	
	set "Arch=x64" & (If "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set Arch=x86)
	if %Arch%==x86 %ch% {0c} Нет поддержки x32 систем. Используйте старые версии на свой риск. Найти можно на NNM.{\n}{0c} Будет выполнен выход.{\n#}&& call :Pause && exit
		
	reg query "HKU\S-1-5-19" >nul 2>&1 || nircmd elevate "%~f0" && exit
	
rem Проверка, если открылся в terminal uwp
	if defined WT_SESSION (
		%ch% {04} Открыто в Терминале. Должно быть открыто в CMD.{\n #}
		%ch% {04} Закройте и заново откройте этот файл.{\n #}
		%ch% {04} Позже, в настройках Терминала Вы можете обратно восстановить открытие в Терминале.{\n #}
		reg add "HKCU\Console\%%%%Startup" /v "DelegationConsole" /t REG_SZ /d "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" /f >nul
		reg add "HKCU\Console\%%%%Startup" /v "DelegationTerminal" /t REG_SZ /d "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" /f >nul
		call :Pause && exit
	)
	
rem Темный заголовок для TI программ
	reg add "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t reg_dword /d 0 /f >nul 2>&1
	sc qc TrustedInstaller | find /i "DISABLED" && (
		sc config TrustedInstaller start=demand
		net start TrustedInstaller
		timeout /t 2 /nobreak >nul
	)
	
	if /i "%USERNAME%" neq "%COMPUTERNAME%$" NSudoLG -U:T -P:E -UseCurrentConsole %0 && exit
	
	set "Version=15.2"
	set "DateProgram=17.05.25"
rem Ширина / Высота
	Mode 78,49
	for /f "tokens=4 delims=[] " %%v in ('ver') do set "NumberWin=%%v" & set "NumberWin=!NumberWin:*0.0.=!"
	nircmd win center process cmd.exe & nircmd win settext foreground "DK | v. %Version% | %DateProgram% | %NumberWin% | By Vlado"
	
	call :NullVar ArgNsudo ThisW7 MainFolder1 MainFolder2 ProcList Maintenance Scan Verification Cleanup
rem C - если отключён UAC / E - если включён UAC
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" | find /i "0x0" >nul 2>&1 && set "ArgNsudo=C" || set "ArgNsudo=E"
rem Проверка Windows 7
	reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "ProductName" | find /i "Windows 7" >nul 2>&1 && set "ThisW7=Yes"
	
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (set "MainFolder1=04") else (set "MainFolder1=0a")
	if exist "%SystemDrive%\Program Files\Windows Defender" (set "MainFolder2=04") else (set "MainFolder2=0a")

	for /f "skip=3 tokens=1" %%a in ('tasklist') do set "ProcList=!ProcList! %%a "
	for %%p in (SmartScreen MsMpEng SgrmBroker MsSense NisSrv MpCmdRun MPSigStub SecurityHealthSystray SecurityHealthService SecurityHealthHost MpDefenderCoreService) do (
	if "!ProcList!"=="!ProcList:%%p.exe =!" (set "%%~pP=0a") else (set "%%~pP=0c"))
	
	set "ListWDServ=WinDefend MDCoreSvc WdNisSvc Sense wscsvc SgrmBroker SecurityHealthService webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent MsSecWfp MsSecFlt MsSecCore"
	for %%x in (%ListWDServ%) do reg query "HKLM\System\CurrentControlSet\Services\%%~x" >nul 2>&1 && set "%%~x=0c" || set "%%~x=0a"
	del /q "%SystemDrive%\latestVersion.bat" >nul 2>&1

	set PathTask=%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender
	if not exist "%PathTask%\Windows Defender Cache Maintenance" (set "Maintenance=0a") else (set "Maintenance=0c")
	if not exist "%PathTask%\Windows Defender Scheduled Scan" (set "Scan=0a") else (set "Scan=0c")
	if not exist "%PathTask%\Windows Defender Verification" (set "Verification=0a") else (set "Verification=0c")
	if not exist "%PathTask%\Windows Defender Cleanup" (set "Cleanup=0a") else (set "Cleanup=0c")

	if defined ThisW7 (
		%ch%  {\n}{0c} Поддержка Windows 7 ограничена. В ней не создается резервная копия.{\n#}
		%ch% {0c} Не используется Unlocker и драйвер. Использовать на свой риск.{\n#}{\n#}
	)

	%ch% {03}Главные папки:{\n #}
	%ch% {%MainFolder1%} %AllUsersProfile%\Microsoft\Windows Defender{\n #}
	%ch% {%MainFolder2%} %SystemDrive%\Program Files\Windows Defender{\n #}

	%ch% {\n}{03}Процессы:{\n #}
	%ch% {%MpCmdRunP%} MpCmdRun {%SmartScreenP%} SmartScreen {%SecurityHealthSystrayP%} SecurityHealthSystray {%SecurityHealthHostP%} SecurityHealthHost{\n #}

	%ch% {\n}{03}Службы и их процессы:{\n #}
	%ch% {%WinDefend%} WinDefend {08} ^> {%MsMpEngP%}MsMpEng.exe{\n #}
	%ch% {%MDCoreSvc%} MDCoreSvc {08} ^> {%MpDefenderCoreServiceP%}MpDefenderCoreService.exe{\n #}
	%ch% {%WdNisSvc%} WdNisSvc {08}  ^>{%NisSrvP%} NisSrv.exe{\n #}
	%ch% {%Sense%} Sense {08}     ^> {%MsSenseP%}MsSense.exe{\n #}
	%ch% {%SgrmBroker%} SgrmBroker {08}^> {%SgrmBrokerP%}SgrmBroker.exe{\n #}
	%ch% {%SecurityHealthService%} SecurityHealthService {08}^> {%SecurityHealthServiceP%}SecurityHealthService.exe{\n #}
	%ch% {\n}{%wscsvc%} wscsvc {%webthreatdefsvc%}webthreatdefsvc {%webthreatdefusersvc%}webthreatdefusersvc{\n #}

	%ch% {\n}{03}Драйвера:{\n #}
	%ch% {%WdFilter%} WdFilter {%WdBoot%}WdBoot {%WdNisDrv%}WdNisDrv {%MsSecWfp%}MsSecWfp {%MsSecFlt%}MsSecFlt {%MsSecCore%}MsSecCore {%SgrmAgent%}SgrmAgent{\n #}

	%ch% {\n}{03}Задания в планировщике:{\n #}
	%ch% {%Maintenance%} Windows Defender Cache Maintenance{\n #}
	%ch% {%Scan%} Windows Defender Scheduled Scan{\n #}
	%ch% {%Verification%} Windows Defender Verification{\n #}
	%ch% {%Cleanup%} Windows Defender Cleanup{\n #}

	%ch% {\n}{08} ***************************************************************************{\n #}

	%ch% {09} 1. {04}Удалить Защитник {0f}[если все зеленое в программе - значит, удалено]{\n #}
	%ch% {09} 2. {08}Проверить состояние папок и файлов Защитника{\n #}
	%ch% {09} 3. {08}Проверить обновления{\n #}
	%ch% {09} 4. {0e}Восстановление Защитника / Удаление Безопасность и др.{\n #}
	%ch% {09} 5. {06}Использовать драйвер DK{\n #}
	%ch% {09} 6. {05}Discord и другой софт{\n #}

	set "input=" & set /p input=
	if not defined input goto Start
	if "%input%"=="1" cls && goto StartProcessRemove
	if "%input%"=="2" cls && goto Catalogs
	if "%input%"=="3" cls && goto CheckUpdate
	if "%input%"=="4" cls && goto ManageDefender
	if "%input%"=="5" cls && goto UseKernelDrv
	if "%input%"=="6" NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c start https://eject37.github.io/vlado/ & goto Start
	cls & %ch% {0c} Такой функции не существует{\n #}& timeout /t 2 >nul & goto Start

rem .............................................................................................................................
:AddExclusionDef
rem # В методе есть проверка после добавления в исключения. Если не добавилось после команды — отмена действий. Причина - на Unlocker заругается и не выйдет его использовать.
rem # Вручную в таком случае необходимо внести в исключения системный диск через параметры defender.
rem # Такое может быть из-за различных состояний defender, непопулярных и редких, но имеющих место быть из-за которых не добавляет в исключения официальный командлетом.
rem # Либо MS сама может заблокировать в будущем добавления в исключения через CMD. От них можно ожидать и этого.
	sc query WinDefend | find /i "RUNNING" >nul 2>&1 && (
			%ch%    {03} Добавляем в исключения{\n #}{\n #}
			NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "[System.IO.DriveInfo]::GetDrives() | ForEach-Object { Add-MpPreference -ExclusionPath $_.Name }; Start-Sleep -Milliseconds 1000" >nul 2>&1
			reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" | find /i "%SystemDrive%\" >nul 2>&1 || %ch% {0c} Ошибка добавления в исключения Защитника. {#}{\n}{0c} Необходимо вручную добавить в исключения системный диск.{\n#}&& call :Pause && goto Start
	)
	exit /b

:StartProcessRemove
rem Если это Win 7 - пропуск Unlocker'а, пропуск создания копии, пропуск добавления в исключения. Не требуется на этой Windows.
	if defined ThisW7 goto SkipUnlockerAndExclAndBackup
	
rem Если раздел драйвера filter и раздел wd от defender существуют (оба) и если не найден в исключениях системный диск - добавляем в исключения.
	reg query HKLM\System\CurrentControlset\Services\WdFilter >nul 2>&1 && reg query "HKLM\Software\Microsoft\Windows Defender" >nul 2>&1 && (
		reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" | find /i "%SystemDrive%\" >nul 2>&1 || (
			call :AddExclusionDef
		)
	)
	
	7z x -aoa -bso0 -bsp1 "DKT.zip" -p"DDK" "Unlocker.exe" >nul
	Unlocker /CurrentDiskSize

	if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
		if not exist "%SystemDrive%\Program Files\Windows Defender" (
			goto SkipUnlockerAndExclAndBackup
		)
	)

rem Пропускаем создание копии. Если нет веток. Если нет файла. Множественная проверка на то, выполнялось ли удаление хотя бы 1 раз.
	set "flag=0"
	reg query "HKLM\Software\Microsoft\Windows Advanced Threat Protection" >nul 2>&1 && set "flag=1"
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" >nul 2>&1 && set "flag=1"
	reg query "HKCR\Directory\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && set "flag=1"
	if exist "%SystemRoot%\System32\SecurityHealthService.exe" set "flag=1"
	if not %flag%==1 goto StartUnlockerAndSkipBackup

	if not exist "%SystemDrive%\WDefenderBackup" (
			if not exist Unlocker.exe %ch% {0c} Unlocker.exe не найден в папке Work, будет выполнен возврат{\n#}&& call :Pause && goto Start
rem Предложение создания копии, если она еще не создана. / # Yes: 0 | No: 1 | Cancel: 2
			Unlocker /mbox YesNoCancel "Внимательно прочитайте текстовый документ рядом с .bat файлом^!\n\nКопию можно НЕ СОЗДАВАТЬ, если:\n1. Не обновляте Windows [без Защитника некоторые обновления могут не устанавливаться]\n2. Защитник не нужен в будущем\n3. Умеете установить Windows на виртуальную машину и забрать оттуда копию\n\nСоздать копию перед удалением?"
			if errorlevel 2 goto Start
			if errorlevel 1 goto StartUnlockerAndSkipBackup
			if errorlevel 0 call :CreateBackupDefender
rem # /unlock завершает принудительно все процессы, которые "держут" папку, чтобы ее можно было скопировать полностью. Иначе часть файлов не сможет скопироваться из-за того, что занята. Есть проблема разблокировки через unlock:
rem # После разблокировки папки некорректно завершается служба WinDefend [MsMpEng.exe] - нужно стартануть службу после использования unlock.
rem # Если не стартовать службу после ее неккоректного завершения - будет дооооооолгий запуск программ и невозможность использовать Unlocker в дальнейшем. И любого другого софта в целом. Все лагает и запускается очень долго. Намеренный шаг от MS, чтобы не отключали Defender базовыми средствами по типу политики ГП "Выключить антивирусную программу Microsoft Defender". В политике об этом прямо и написано в самом конце ее описания - "...Включение или отключение этой политики может привести к непредвиденному или неподдерживаемом поведению.."
			sc query WinDefend | find /i "STOPPED" >nul 2>&1 && (
					sc start WinDefend >nul 2>&1
					sc start WinDefend >nul 2>&1	
			)

	) else (
			%ch%    {0a} Резервная копия уже существует. Если это старая копия - удалите ее с диска и повторите процесс создания копии{\n#}
			call :Pause
	)

:StartUnlockerAndSkipBackup
	if not exist Unlocker.exe %ch% {0c} Unlocker.exe не найден в папке Work, будет выполнен возврат{\n#}&& call :Pause && goto Start
	Unlocker /DеlWD

	for %%d in ("%AllUsersProfile%\Microsoft\Windows Security Health", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender") do (
		if exist %%d (
			%ch%    {08} Папка %%d не удалилась{\n #}
			%ch%    {0c} Повторное удаление{\n #}{\n #}
			timeout /t 2 /nobreak >nul
			Unlocker /DеlWD
		)
	)

:SkipUnlockerAndExclAndBackup
rem # Переход сюда в двух случаях:
rem 1 - Если это Windows 7. Для Windows 7 создание копии пропускается , как и использование Unlocker в целом.
rem 2 - Если нет папки Windows Defender в ProgramData и в ProgramFiles [выполнялось удаление хотя бы 1 раз]
	%ch%    {03} Выполняется удаление{\n #}{\n #}
(
	for %%x in (%ListWDServ%) do sc config "%%~x" start= disabled & sc stop "%%~x" & sc delete "%%~x" & reg delete "HKLM\System\CurrentControlset\Services\%%~x" /f
	rd /s /q "%SystemRoot%\System32\drivers\wd"

	for %%d in ("Windows Defender" "Windows Defender Advanced Threat Protection" "Windows Security Health" "Storage Health") do (
		rd /s /q "%AllUsersProfile%\Microsoft\%%~d")

	for %%d in ("Windows Defender" "Windows Defender Sleep" "Windows Defender Advanced Threat Protection" "Windows Security" "PCHealthCheck" "Microsoft Update Health Tools") do (
		rd /s /q "%SystemDrive%\Program Files\%%~d")

	for %%d in ("Windows Defender" "Windows Defender Advanced Threat Protection") do (
		rd /s /q "%SystemDrive%\Program Files (x86)\%%~d")

	for %%d in ("HealthAttestationClient" "SecurityHealth" "WebThreatDefSvc" "Sgrm") do (
		rd /s /q "%SystemRoot%\System32\%%~d")

	rd /s /q "%SystemRoot%\security\database"
	rd /s /q "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender"
	rd /s /q "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	rd /s /q "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender"
	rd /s /q "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender"
	rd /s /q "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender"
	rd /s /q "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance"

rem Переименование 4 файлов
	ren "%SystemRoot%\System32\SecurityHealthService.exe" "SecurityHealthService.exe_fuck"
	ren "%SystemRoot%\System32\smartscreenps.dll" smartscreenps.dll_fuck
	ren "%SystemRoot%\System32\wscapi.dll" wscapi.dll_fuck
	ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen.exedel"

	del /f /q "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim"
	del /f /q "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim"

rem Удаление файлов от Defender / Центра Безопасности и SmartScreen + 4 файла переименованных
	for %%f in (
		SecurityHealthService.exe SecurityHealthSystray.exe SecurityHealthHost.exe
		SecurityHealthAgent.dll SecurityHealthSSO.dll SecurityHealthProxyStub.dll smartscreen.dll wscisvif.dll
		wscproxystub.dll smartscreenps.dll wscapi.dll windowsdefenderapplicationguardcsp.dll wscsvc.dll SecurityHealthCore.dll
		SecurityHealthSsoUdk.dll SecurityHealthUdk.dll smartscreen.exe

		SecurityHealthService.exe_fuck
		smartscreenps.dll_fuck
		wscapi.dll_fuck
		smartscreen.exedel
	) do del /f /q "%SystemRoot%\System32\%%f" "%SystemRoot%\SysWOW64\%%f"

rem Планировщик / Реестр
	for %%s in ("Windows Defender Cache Maintenance" "Windows Defender Cleanup" "Windows Defender Scheduled Scan" "Windows Defender Verification"
	) do schtasks /Delete /TN "Microsoft\Windows\Windows Defender\%%~s" /f
	schtasks /Delete /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /f

	reg delete "HKLM\Software\Microsoft\Windows Defender" /f
	reg delete "HKLM\Software\Microsoft\Windows Defender Security Center" /f
	reg delete "HKLM\Software\Microsoft\Windows Advanced Threat Protection" /f
	reg delete "HKLM\Software\Microsoft\Windows Security Health" /f

	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" /f
	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" /f

	reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f

	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /f

	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /f

rem Удаление надписи в параметрах
	REM reg delete "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" /f

rem Удаление из Панели управления элемента Windows Defender [Windows 8.1]
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	reg delete "HKCR\CLSID\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f

) >nul 2>&1

:FinishDelete
	if defined ThisW7 call :Pause && goto Start
	Unlocker /NewDiskSize
	sc start VMTools >nul 2>&1
	sc start VMTools >nul 2>&1
rem Создание в автозапуск самоисчезающих [разовых] команд для подчистки служб после ребута ПК
	reg query "HKLM\System\CurrentControlset\Services\WdFilter" >nul 2>&1 && (
		call :CreateRunOnceDelReg
		echo.
		%ch%    {04} Часть служб не удалена. Требуется перезапуск ПК для подчистки служб^^!{\n #}
		%ch%    {04} Не удаляйте .bat файл и папку Work до перезапуска ПК^^!{\n #}
	) || (
		%ch%    {08} Ориентируйтесь на состояние папок {0f}- цифра 2 {0f}и главное меню{\n #}
		%ch%    {02} Безопасность из пуска можно удалить в пункте 4 - 2{\n #}
	)
	del /q Unlocker.exe >nul 2>&1
rem Возвращаем цвет заголовка по-умолчанию для TI программ. Нет в чистой Windows
	reg delete "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f >nul 2>&1
	call :Pause && goto Start
 
 :CreateRunOnceDelReg
	set "RegKey=HKLM\System\CurrentControlSet\Services"
rem Двойная очистка реестра
rem Вносятся записи в RunOnce [разовый запуск] после ребута ПК , которые пытаются удалить неудалённые ранее разделы служб из реестра.
	for %%p in (RegClean RegClean1) do reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "%%p" /t reg_sz /f /d "\"%~dp0Work\NSudoLG.exe\" -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c \"timeout /t 3 /nobreak ^& reg delete %RegKey%\WdFilter /f ^& reg delete %RegKey%\WinDefend /f ^& reg delete %RegKey%\WdNisDrv /f ^& reg delete %RegKey%\MDCoreSvc /f ^& reg delete %RegKey%\WdNisSvc /f ^& reg delete %RegKey%\WdBoot /f\"" >nul
rem MessageBox-напоминание, что необходимо запустить DK после перезагрузки, чтобы проверить состояние служб после подчистки
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "DKRUN" /t reg_sz /f /d "\"%~dp0Work\NSudoLG.exe\" -U:C -ShowWindowMode:Hide -Wait cmd.exe /c \"timeout /t 6 /nobreak ^& msg * Запустите DK и проверьте состояние служб. Если что-то осталось красным - воспользуйтесь драйвером."" >nul

	exit /b

rem ..................................... Конец удаления .....................................

:ManageDefender
	cls & call :NullVar HideSettigns
	2>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" | find /i "windowsdefender" >nul 2>&1 && set "HideSettigns={0a}скрыт" || set "HideSettigns={0c}не скрыт"
	del /q Unlocker.exe SelectedPath.txt >nul 2>&1

	%ch% {09} 1. {0a}Восстановить защитник из копии{\n#}{\n#}
	%ch% {09} 2. {08}Удалить приложение Безопасность {0b}с подтверждением {08}(значок в пуске){\n#}
	%ch% {09} 3. {08}Раздел Безопасность в Параметрах %HideSettigns%{\n#}
	%ch% {09} 4. {08}Отключить VBS (Безопасность на основе виртуализации){\n#}
	%ch% {09} 5. {08}Удалить папки Защитника из хранилища WinSxS {0b}с подтверждением{\n#}
	%ch% {\n}{0e} [Enter] - {08}Вернуться в главное меню{\n#}
	set "input=" & set /p input=
	if not defined input goto Start
	if "%input%"=="1" goto RestoreDefender
	if "%input%"=="2" goto SecHealthUI
	if "%input%"=="3" call :HideShowInSettings
	if "%input%"=="4" goto VBSDis
	if "%input%"=="5" goto WinSxSFolders
	goto ManageDefender

:WinSxSFolders
	%ch% {\n} Если не создавалась рез. копия, удаление папок из WinSxS сломает обновления.{\n #}
	%ch%  Позволяет очистить дополнительное место. ~300-400 мб.{\n #}
	%ch% {08} 1. {0c}Удалить папки из WinSxS{\n #}
	%ch% {08} 2. Отмена удаления папок{\n #}
	choice /c 12 /n /m " "
	if errorlevel 2 goto ManageDefender

rem Удаление папок из хранилища WinSxS с бОльшей вероятностью сломает установку накопительных обновлений.
	for %%i in (windows-defender, windows-senseclient-service, windows-dynamic-image) do (
			for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*%%i*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	)
	goto ManageDefender

:HideShowInSettings
	if defined ThisW7 %ch% {0c} Не требуется в этой версии{\n #}&& call :Pause && goto Start
	chcp 437 >nul
	PowerShell -noprof -nonint -command "$p='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $n='SettingsPageVisibility'; $t='windowsdefender'; $v=(Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue).$n; Get-Process SystemSettings -ErrorAction SilentlyContinue | Stop-Process -Force; if (-not $v) {New-ItemProperty -Path $p -Name $n -PropertyType String -Value ('hide:' + $t) -Force; exit} elseif ($v -eq ('hide:' + $t)) {Remove-ItemProperty -Path $p -Name $n -Force; exit} elseif ($v -like '*hide:*' -and $v -like ('*' + $t + '*')) { $prefix='hide:'; $rest=$v.Substring($prefix.Length); $items = $rest -split ';' | Where-Object { $_ -ne $t -and $_ -ne '' }; if ($items.Count -eq 0) { Remove-ItemProperty -Path $p -Name $n -Force } else { Set-ItemProperty -Path $p -Name $n -Value ($prefix + ($items -join ';')) -Force }; exit } else { if ($v.StartsWith('hide:')) { Set-ItemProperty -Path $p -Name $n -Value ($v + ';' + $t) -Force } else { Set-ItemProperty -Path $p -Name $n -Value ('hide:' + $v + ';' + $t) -Force } }" >nul 2>&1
	chcp 65001 >nul
	exit /b

:SecHealthUI
	if defined ThisW7 %ch% {0c} Не требуется в этой версии{\n #}&& call :Pause && goto Start
	call :NullVar CurrentBuild SID NameSecHealth NameAppRep
	for /f "tokens=2*" %%a in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "CurrentBuild" 2^>nul') do set CurrentBuild=%%b
	set /a CurrentBuild=%CurrentBuild%
	if %CurrentBuild% lss 10240 %ch%    {04} Не требуется на данной версии Windows{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender

	for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoLogonSID" 2^>nul') do set "SID=%%a"
	if not defined SID for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v "LastLoggedOnUserSID" 2^>nul') do set "SID=%%a"
	if not defined SID %ch%    {04} SID не был получен, отмена удаления приложений{\n #}&& timeout /t 5 /nobreak >nul && goto ManageDefender

	%ch% {\n} После удаления приложения зайти в настройки защитника будет {04}невозможно.{\n #}
	%ch% {08} 1. {0e}Удалить Безопасность Windows {04}[нет восстановления этому действию в DK^^!]{\n#}
	%ch% {08} 2. Отмена{\n#}{\n#}
	choice /c 12 /n /m " "
	if errorlevel 2 goto ManageDefender

	cls && Mode 81,49
rem Получаем имя SystemApp Безопасность Windows [SecHealthUI] - Оснастка для управления антивирусной программой Windows Defender
	%ch% {\n}   {03} Удаляем Безопасность Windows{\n #}
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*SecHealthUI*" /k^|findstr ^H`) do set NameSecHealth=%%~nxn
	if not defined NameSecHealth %ch%    {02} Приложение Безопасность Windows удалено{\n #}{\n #}&& goto AppRepSys

	%ch% {08} %NameSecHealth%{\n #}{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameSecHealth%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameSecHealth%" /f >nul
	NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *SecHealthUI* | Remove-AppxPackage"
	NSudoLG -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *SecHealthUI* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*SecHealthUI*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem Эти папки можно удалять. Восстанавливаются сами, если восстановить приложение.
	for /f "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"
	for /f "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"

:AppRepSys
rem Получаем имя SystemApp AppRep [SmartScreen]
	%ch%    {03} Удаляем SmartScreen защитника Windows{\n #}
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do set NameAppRep=%%~nxn
	if not defined NameAppRep %ch%    {02} Приложение SmartScreen защитника Windows удалено{\n #}&& echo. && call :Pause && goto ManageDefender

	%ch% {08} %NameAppRep%{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameAppRep%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameAppRep%" /f >nul
	NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *Apprep.ChxApp* | Remove-AppxPackage"
	NSudoLG -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *Apprep.ChxApp* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem Эти папки можно удалять, восстанавливаются сами, если восстановить приложение.
	for /f "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	for /f "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	call :Pause && goto ManageDefender

 rem ..................................... Создание резервной копии .....................................
:CreateBackupDefender
	%ch%    {09} Создаём резервную копию{\n #}
	set "PathToBackup="
	set "PathToBackup=%SystemDrive%\WDefenderBackup"
	
	Unlocker /unlock "%AllUsersProfile%\Microsoft\Windows Defender" "%SystemDrive%\Program Files\Windows Defender" "%SystemDrive%\Program Files (x86)\Windows Defender"

	for %%d in (
	"Windows Defender"
	"Windows Defender Advanced Threat Protection"
	"Windows Security Health"
	"Storage Health") do xcopy "%AllUsersProfile%\Microsoft\%%~d" "%PathToBackup%\Folder\ProgramData\Microsoft\%%~d" /s /e /h /y /i >nul 2>&1

	for %%d in (
	"Windows Defender"
	"Windows Defender Sleep"
	"Windows Defender Advanced Threat Protection"
	"Windows Security"
	"PCHealthCheck"
	"Microsoft Update Health Tools") do xcopy "%SystemDrive%\Program Files\%%~d" "%PathToBackup%\Folder\Program Files\%%~d" /s /e /h /y /i >nul 2>&1

	for %%d in (
	"Windows Defender"
	"Windows Defender Advanced Threat Protection"
	) do xcopy "%SystemDrive%\Program Files (x86)\%%~d" "%PathToBackup%\Folder\Program Files (x86)\%%~d" /s /e /h /y /i >nul 2>&1

rem Функция CheckStateBackup проверяет, существуют ли папки или файлы внутри скопированной папки из ProgramData
	call :CheckStateBackup

(
	xcopy "%SystemRoot%\security\database" "%PathToBackup%\Folder\Windows\security\database" /s /e /h /y /i
	
	xcopy "%SystemRoot%\System32\HealthAttestationClient" "%PathToBackup%\Folder\System32\HealthAttestationClient" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\SecurityHealth" "%PathToBackup%\Folder\System32\SecurityHealth" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\WebThreatDefSvc" "%PathToBackup%\Folder\System32\WebThreatDefSvc" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\Sgrm" "%PathToBackup%\Folder\System32\Sgrm" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" "%PathToBackup%\Folder\System32\WindowsPowerShell\v1.0\Modules\Defender" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%PathToBackup%\Folder\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" "%PathToBackup%\Folder\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender"
	xcopy "%SystemRoot%\System32\drivers\wd" "%PathToBackup%\Folder\System32\drivers\wd" /s /e /h /y /i
	xcopy "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" "%PathToBackup%\Folder\System32\Tasks\Microsoft\Windows\Windows Defender" /s /e /h /y /i
	
	xcopy "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender" "%PathToBackup%\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender" /s /e /h /y /i
	xcopy "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%PathToBackup%\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance" /s /e /h /y /i

rem Копирование файлов из System32 / SysWow64 / Windows\Containers
	md "%PathToBackup%\Files\System32"
	md "%PathToBackup%\Files\SysWOW64"
	md "%PathToBackup%\Files\Windows\Containers"
	md "%PathToBackup%\Files\Windows\Containers\serviced"
	for %%f in (
	SecurityHealthService.exe SecurityHealthSystray.exe
	SecurityHealthHost.exe SecurityHealthAgent.dll
	SecurityHealthSSO.dll SecurityHealthProxyStub.dll
	smartscreen.dll wscisvif.dll wscproxystub.dll
	smartscreenps.dll wscapi.dll windowsdefenderapplicationguardcsp.dll
	wscsvc.dll SecurityHealthCore.dll SecurityHealthSsoUdk.dll
	SecurityHealthUdk.dll smartscreen.exe) do (
		copy /y "%SystemRoot%\System32\%%f" "%PathToBackup%\Files\System32\"
		copy /y "%SystemRoot%\SysWOW64\%%f" "%PathToBackup%\Files\SysWow64\"
	)

	copy /y "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" "%PathToBackup%\Files\Windows\Containers\"
	copy /y "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" "%PathToBackup%\Files\Windows\Containers\serviced"
) >nul 2>&1

rem Службы / Драйвера
	md "%PathToBackup%\ServicesDrivers"
	md "%PathToBackup%\RegEdit"
	for %%x in (%ListWDServ%) do reg export "HKLM\System\CurrentControlSet\Services\%%x" "%PathToBackup%\ServicesDrivers\%%x.reg" >nul 2>&1
(
	reg export "HKCR\*\shellex\ContextMenuHandlers\EPP" "%PathToBackup%\RegEdit\1.reg"
	reg export "HKCR\Directory\shellex\ContextMenuHandlers\EPP" "%PathToBackup%\RegEdit\2.reg"
	reg export "HKCR\Drive\shellex\ContextMenuHandlers\EPP" "%PathToBackup%\RegEdit\3.reg"
	reg export "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" "%PathToBackup%\RegEdit\4.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "%PathToBackup%\RegEdit\5.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "%PathToBackup%\RegEdit\6.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" "%PathToBackup%\RegEdit\7.reg"
	reg export "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" "%PathToBackup%\RegEdit\8.reg"
	reg export "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" "%PathToBackup%\RegEdit\9.reg"
	reg export "HKLM\Software\Microsoft\Windows Defender" "%PathToBackup%\RegEdit\10.reg"
	reg export "HKLM\Software\Microsoft\Windows Defender Security Center" "%PathToBackup%\RegEdit\11.reg"
	reg export "HKLM\Software\Microsoft\Windows Advanced Threat Protection" "%PathToBackup%\RegEdit\12.reg"
	reg export "HKLM\Software\Microsoft\Windows Security Health" "%PathToBackup%\RegEdit\13.reg"
	reg export "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" "%PathToBackup%\RegEdit\14.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" "%PathToBackup%\RegEdit\15.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" "%PathToBackup%\RegEdit\16.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" "%PathToBackup%\RegEdit\17.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" "%PathToBackup%\RegEdit\18.reg"
) >nul 2>&1

rem # Экспорт CLSID. Нужно это, потому что Win 10 Tweaker / ModernTweaker удаляют эти CLSID при использовании твика "Очистки реестра"
	md "%PathToBackup%\CLSID"
	set "Counter=1"
	set "Counter64=1"
	for %%i in (
		08728914-3F57-4D52-9E31-49DAECA5A80A 		10964DDD-6A53-4C60-917F-7B5723014344 		17072F7B-9ABE-4A74-A261-1EB76B55107A
		195B4D07-3DE2-4744-BBF2-D90121AE785B 	2781761E-28E0-4109-99FE-B9D127C57AFE 		2981a36e-f22d-11e5-9ce9-5e5517507c66
		2DCD7FDB-8809-48E4-8E4F-3157C57CF987 		2EF44DE8-80C9-42D9-8541-F40EF0862FA3 		3213CD15-4DF2-415F-83F2-9FC58F3AEB3A
		3522D7AF-4617-4237-AAD8-5860231FC9BA 		361290c0-cb1b-49ae-9f3e-ba1cbe5dab35 			36383E77-35C2-4B45-8277-329E4BEDF47F
		3886CA90-AB09-49D1-A047-7A62D096D275		3CD3CA1E-2232-4BBF-A733-18B700409DA0 	45F2C32F-ED16-4C94-8493-D72EF93A051B
		4DB116D1-9B24-4DFC-946B-BFE03E852002 		5ffab5c8-9a36-4b65-9fc6-fb69f451f99c 				6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF
		6D40A6F9-3D32-4FCB-8A86-BE992E03DC76 	7E66DBEF-2474-4E82-919B-9A855F4C2FE8 		82345212-6ACA-4B38-8CD7-BF9DE8ED07BD
		849F5497-5C61-4023-8E10-A28F1A8C6A70 		88866959-07B0-4ED8-8EF5-54BC7443D28C 		8a696d12-576b-422e-9712-01b9dd84b446
		8C38232E-3A45-4A27-92B0-1A16A975F669 		8E67B5C5-BAD3-4263-9F80-F769D50884F7 		A2D75874-6750-4931-94C1-C99D3BC9D0C7
		a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d 			A7C452EF-8E9F-42EB-9F2B-245613CA0DC9 		C8DFF91D-B243-4797-BAE6-C461B65EDED3
		D5F7E36B-5B38-445D-A50F-439B8FCBB87A 	DACA056E-216A-4FD1-84A6-C306A017ECEC 	DBF393FC-230C-46CC-8A85-E9C599A81EFB
		E041C90B-68BA-42C9-991E-477B73A75C90 		E476E4C0-409C-43CD-BBC0-5905B4138494 		F2102C37-90C3-450C-B3F6-92BE1693BDF2
		F80FC80C-6A04-46FB-8555-D769E334E9FC 		FEEE9C23-C4E2-4A34-8C73-FE8F9786C8B4 		D8559EB9-20C0-410E-BEDA-7ED416AECC2A) do (
			reg export "HKCR\CLSID\{%%i}" "%PathToBackup%\CLSID\!Counter!.reg" >nul 2>&1
			reg export "HKCR\WOW6432Node\CLSID\{%%i}" "%PathToBackup%\CLSID\W64!Counter64!.reg" >nul 2>&1
			set /a Counter+=1
			set /a Counter64+=1
	)
	reg export "HKCR\windowsdefender" "%PathToBackup%\CLSID\windowsdefender.reg" >nul 2>&1
	reg export "HKCR\WdMam" "%PathToBackup%\CLSID\WdMam.reg" >nul 2>&1

	for /d %%i in ("%SystemRoot%\WinSxS\*windows-defender*") do xcopy "%%i" "%PathToBackup%\Folder\WinSxS\%%~nxi" /i /e /h /y >nul 2>&1
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-senseclient-service*") do xcopy "%%i" "%PathToBackup%\Folder\WinSxS\%%~nxi" /i /e /h /y >nul 2>&1
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-dynamic-image*") do xcopy "%%i" "%PathToBackup%\Folder\WinSxS\%%~nxi" /i /e /h /y >nul 2>&1
	
	%ch%    {08} Копия создана в %SystemDrive%\WDefenderBackup{\n #}{\n #}
	exit /b

 rem ..................................... Восстановление из копии .....................................
 
:RestoreDefender
	if defined ThisW7 %ch% {0c} Нет восстановления для этой версии{\n #}&& call :Pause && goto Start
	sc query WinDefend | find /i "RUNNING" >nul 2>&1 && (
		%ch% {0c} Запущена служба WinDefend. Defender не удалён.{\n#}
		%ch% {0b} Нельзя восстанавливать Defender поверх себя.{\n#}
		%ch% {08} Сначала выполните удаление.{\n#}
		call :Pause && goto ManageDefender
	)
	if not exist "%SystemRoot%\System32\config\systemprofile\Desktop" md "%SystemRoot%\System32\config\systemprofile\Desktop"
	%ch% {0c} Убедитесь, что выбранная рез. копия была создана на этой же версии Windows.{\n #}
rem Выбор папки и проверка выбранной папки на корректность резервной копии
	call :NullVar BackupFolder
	7z x -aoa -bso0 -bsp1 "DKT.zip" -p"DDK" "Unlocker.exe" >nul
	Unlocker /SelectFolder "Выберите папку WDefenderBackup с ранее созданной резервной копией Windows Defender."
	echo.
	if not exist SelectedPath.txt %ch% {04} Вы ничего не выбрали, возврат обратно.{\n #}&&call :Pause && goto ManageDefender
	for /f "tokens=*" %%a in (SelectedPath.txt) do set "BackupFolder=%%a"
	if not exist "%BackupFolder%\Folder" %ch% {04} Неверная папка резервной копии.{\n #}&&call :Pause && goto ManageDefender
	if not exist "%BackupFolder%\ServicesDrivers" %ch% {04} Неверная папка резервной копии.{\n #}&&call :Pause && goto ManageDefender
	
	%ch% {03} Выполняем восстановление из копии{\n #}{\n #}
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

	for %%f in ("RegEdit\*.reg") do reg import "%%f"
	for %%f in ("ServicesDrivers\*.reg") do reg import "%%f"
	for %%f in ("CLSID\*.reg") do reg import "%%f"

	reg delete "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /f
	reg delete "HKLM\Software\Policies\Microsoft\MRT" /f
	
) >nul 2>&1

	popd
	
rem Используется NSudoLG потому что HKCU. HKCU у юзера свой. У TI - свой. Здесь от админа выполнение.
	NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f
	NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /f
	
	del /q Unlocker.exe SelectedPath.txt >nul 2>&1
	
	%ch% {0f} Добавить все диски в исключения защитника?{\n #}
	%ch% {\n} Полезно, чтобы после восстановления защитник не удалил Ваши файлы{\n #}
	%ch% {08} 1. {0a}Добавить в исключения{\n #}
	%ch% {08} 2. Отмена{\n #}
	choice /c 12 /n /m " "
	if "%errorlevel%"=="1" call :AddExclusionRestore
	if "%errorlevel%"=="2" %ch% {08} Вы пропустили добавление в исключения{\n #}
	%ch% {0a} Требуется перезапуск ПК{\n #}&& call :Pause && goto Start
	call :Pause && goto Start

 rem ..................................... Состояние папок и файлов .....................................
 
:Catalogs
	for /l %%i in (0,1,17) do set "Folder%%i="
	for /l %%i in (1,1,18) do set "File%%i="
rem Папки
	if exist "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" (set "Folder0=0c") else (set "Folder0=0a")
	
	if exist "%SystemRoot%\System32\HealthAttestationClient" (set "Folder1=0c") else (set "Folder1=0a")
	if exist "%SystemRoot%\System32\SecurityHealth" (set "Folder2=0c") else (set "Folder2=0a")
	if exist "%SystemRoot%\System32\WebThreatDefSvc" (set "Folder3=0c") else (set "Folder3=0a")
	if exist "%SystemRoot%\System32\Sgrm" (set "Folder4=0c") else (set "Folder4=0a")
	if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" (set "Folder5=0c") else (set "Folder5=0a")
	if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" (set "Folder6=0c") else (set "Folder6=0a")
	if exist "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" (set "Folder7=0c") else (set "Folder7=0a")
	if exist "%ProgramFiles%\Windows Defender Sleep" (set "Folder8=0c") else (set "Folder8=0a")
	if exist "%ProgramFiles%\Windows Defender Advanced Threat Protection" (set "Folder9=0c") else (set "Folder9=0a")
	if exist "%ProgramFiles%\Windows Security" (set "Folder10=0c") else (set "Folder10=0a")
	if exist "%ProgramFiles%\PCHealthCheck" (set "Folder11=0c") else (set "Folder11=0a")
	if exist "%ProgramFiles%\Microsoft Update Health Tools" (set "Folder12=0c") else (set "Folder12=0a")
	if exist "%ProgramFiles(x86)%\Windows Defender" (set "Folder13=0c") else (set "Folder13=0a")
	if exist "%ProgramFiles(x86)%\Windows Defender Advanced Threat Protection" (set "Folder14=0c") else (set "Folder14=0a")
	if exist "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" (set "Folder15=0c") else (set "Folder15=0a")
	if exist "%AllUsersProfile%\Microsoft\Windows Security Health" (set "Folder16=0c") else (set "Folder16=0a")
	if exist "%AllUsersProfile%\Microsoft\Storage Health" (set "Folder17=0c") else (set "Folder17=0a")

rem Файлы
	if exist "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" (set "File1=04") else (set "File1=0a")
	if exist "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" (set "File2=04") else (set "File2=0a")
	if exist "%SystemRoot%\System32\SecurityHealthService.exe" (set "File3=04") else (set "File3=0a")
	if exist "%SystemRoot%\System32\SecurityHealthSystray.exe" (set "File4=04") else (set "File4=0a")
	if exist "%SystemRoot%\System32\SecurityHealthHost.exe" (set "File5=04") else (set "File5=0a")
	if exist "%SystemRoot%\System32\SecurityHealthAgent.dll" (set "File6=04") else (set "File6=0a")
	if exist "%SystemRoot%\System32\SecurityHealthSSO.dll" (set "File7=04") else (set "File7=0a")
	if exist "%SystemRoot%\System32\SecurityHealthProxyStub.dll" (set "File8=04") else (set "File8=0a")
	if exist "%SystemRoot%\System32\smartscreen.dll" (set "File9=04") else (set "File9=0a")
	if exist "%SystemRoot%\System32\wscisvif.dll" (set "File10=04") else (set "File10=0a")
	if exist "%SystemRoot%\System32\wscproxystub.dll" (set "File11=04") else (set "File11=0a")
	if exist "%SystemRoot%\System32\smartscreenps.dll" (set "File12=04") else (set "File12=0a")
	if exist "%SystemRoot%\System32\wscapi.dll" (set "File13=04") else (set "File13=0a")
	if exist "%SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll" (set "File14=04") else (set "File14=0a")
	if exist "%SystemRoot%\System32\wscsvc.dll" (set "File15=04") else (set "File15=0a")
	if exist "%SystemRoot%\System32\SecurityHealthCore.dll" (set "File16=04") else (set "File16=0a")
	if exist "%SystemRoot%\System32\SecurityHealthSsoUdk.dll" (set "File17=04") else (set "File17=0a")
	if exist "%SystemRoot%\System32\SecurityHealthUdk.dll" (set "File18=04") else (set "File18=0a")
	
	%ch% {09}Папки в %SystemRoot%\System32{\n #}
	%ch% {%Folder0%} %SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender{\n #}

	%ch% {%Folder1%} %SystemRoot%\System32\HealthAttestationClient{\n #}
	%ch% {%Folder2%} %SystemRoot%\System32\SecurityHealth{\n #}
	%ch% {%Folder3%} %SystemRoot%\System32\WebThreatDefSvc{\n #}
	%ch% {%Folder4%} %SystemRoot%\System32\Sgrm{\n #}
	%ch% {%Folder5%} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender{\n #}
	%ch% {%Folder6%} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance{\n #}
	%ch% {%Folder7%} %SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender{\n #}

	%ch% {\n}{09}Папки в %ProgramFiles%{\n #}
	%ch% {%Folder8%} %ProgramFiles%\Windows Defender Sleep{\n #}
	%ch% {%Folder9%} %ProgramFiles%\Windows Defender Advanced Threat Protection{\n #}
	%ch% {%Folder10%} %ProgramFiles%\Windows Security{\n #}
	%ch% {%Folder11%} %ProgramFiles%\PCHealthCheck{\n #}
	%ch% {%Folder12%} %ProgramFiles%\Microsoft Update Health Tools{\n #}

	%ch% {\n}{09}Папки в %ProgramFiles(x86)%{\n #}
	%ch% {%Folder13%} %ProgramFiles(x86)%\Windows Defender{\n #}
	%ch% {%Folder14%} %ProgramFiles(x86)%\Windows Defender Advanced Threat Protection{\n #}
	
	%ch% {\n}{09}Папки в %AllUsersProfile%{\n #}
	%ch% {%Folder15%} %AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection{\n #}
	%ch% {%Folder16%} %AllUsersProfile%\Microsoft\Windows Security Health{\n #}
	%ch% {%Folder17%} %AllUsersProfile%\Microsoft\Storage Health{\n #}

	%ch% {\n}{09}Файлы{\n #}
	%ch% {%File1%} %SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim{\n #}
	%ch% {%File2%} %SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim{\n #}
	%ch% {%File3%} %SystemRoot%\System32\SecurityHealthService.exe{\n #}
	%ch% {%File4%} %SystemRoot%\System32\SecurityHealthSystray.exe{\n #}
	%ch% {%File5%} %SystemRoot%\System32\SecurityHealthHost.exe{\n #}
	%ch% {%File6%} %SystemRoot%\System32\SecurityHealthAgent.dll{\n #}
	%ch% {%File7%} %SystemRoot%\System32\SecurityHealthSSO.dll{\n #}
	%ch% {%File8%} %SystemRoot%\System32\SecurityHealthProxyStub.dll{\n #}
	%ch% {%File9%} %SystemRoot%\System32\smartscreen.dll{\n #}
	%ch% {%File10%} %SystemRoot%\System32\wscisvif.dll{\n #}
	%ch% {%File11%} %SystemRoot%\System32\wscproxystub.dll{\n #}
	%ch% {%File12%} %SystemRoot%\System32\smartscreenps.dll{\n #}
	%ch% {%File13%} %SystemRoot%\System32\wscapi.dll{\n #}
	%ch% {%File14%} %SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll{\n #}
	%ch% {%File15%} %SystemRoot%\System32\wscsvc.dll{\n #}
	%ch% {%File16%} %SystemRoot%\System32\SecurityHealthCore.dll{\n #}
	%ch% {%File17%} %SystemRoot%\System32\SecurityHealthSsoUdk.dll{\n #}
	%ch% {%File18%} %SystemRoot%\System32\SecurityHealthUdk.dll{\n #}
	call :Pause && goto Start
	
rem .............................................................................................................................
rem === НАЧАЛО МЕТОДОВ =========
:CheckStateBackup
rem Функция проверки после копирования главной папки, есть ли сама папка и есть ли в ней файлы или папки. Вывод версии Windows.
		dir /b "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender" | findstr /r "^" >nul && (
		exit /b
	) || (
		%ch% {04} Папку "%AllUsersProfile%\Microsoft\Windows Defender" скопировать не удалось{\n #}
		%ch% {08} Ваша версия Windows - {03}%NumberWin%{\n #}
		call :Pause
		rd /s /q "%SystemDrive%\WDefenderBackup" >nul 2>&1
		goto Start
	)
:AddExclusionRestore
	echo Windows Registry Editor Version 5.00 > exclusions.reg
	echo. >> exclusions.reg
	echo [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Exclusions\Paths] >> exclusions.reg
	for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        echo "%%d:\\"=dword:00000000>> exclusions.reg)
	)
	if exist exclusions.reg reg import exclusions.reg >nul
	del /q exclusions.reg >nul 2>&1
	exit /b

:CheckUpdate
	cls
rem Проверка наличия curl в папке Work или в папке System32 для проверки обновлений
	if not exist "%SystemRoot%\System32\curl.exe" (
		if not exist "%~dp0Work\curl.exe" (
		%ch% {04} Программа curl не найдена в папке Work и в папке System32.{\n #}
		%ch% {04} Поместите программу в папку System32 или в Work{\n #}
		%ch% {08} Скачать можно тут - https://curl.se/windows/{\n #}
		call :Pause && goto Start
			)
	)
	ping pastebin.com -n 1 -w 1000 |>nul find /i "TTL="|| %ch% {04} Ошибка проверки, нет интернет-соединения.{\n #}&& timeout /t 3 >nul && goto Start
	curl -g -k -L -# -o "%SystemDrive%\latestVersion.bat" "https://pastebin.com/raw/dnENFgmC" >nul 2>&1
	if exist "%SystemDrive%\latestVersion.bat" (
		call "%SystemDrive%\latestVersion.bat"
	) else (
		%ch% {0c} Не скачался файл проверки обновлений{\n #}&& call :Pause && goto Start
	)
	if "%Version%" lss "%latestVersion%" (cls) else (
		%ch% {0a} Обновлений не найдено. У Вас актуальная версия {0f}- {0e}%Version%{\n #}{\n #}
		call :Pause && goto Start
	)
	%ch%  {08} Найдена {0e}новая версия{\n #}
    curl -g -k -L -# -o "%~dp0DefenderKillerNew.bat" "https://github.com/oatmealcookiec/DK/releases/latest/download/DefenderKiller.bat" >nul 2>&1
    if not exist "%~dp0DefenderKillerNew.bat" %ch% {\n #} {0c} Скачивание не удалось. Повторите попытку.{\n #}&& call :Pause && goto Start
	call :Pause
    start "" NSudoLG -U:%ArgNsudo% -ShowWindowMode:Hide cmd /c "timeout /t 2 && del /q "%~f0" && timeout /t 2 && ren "%~dp0DefenderKillerNew.bat" DefenderKiller.bat && start "" "%~dp0DefenderKiller.bat""
    exit

:UseKernelDrv
rem На Win 7 нельзя использовать драйвер - BSOD. На Windows 8 и первых версиях Windows 10 - неизвестно.
	if defined ThisW7 %ch% {0c} Использование драйвера на этой версии Windows невозможно{\n #}&& call :Pause && goto Start
	Mode 93,49 & nircmd win center process cmd.exe

	if exist "%SystemDrive%\Program Files\Windows Defender" %ch% {0b} Для использования драйвера нужно сначала выполнить удаление в пункте 1{\n #}&& call :Pause && goto Start
	
rem Проверяем, отключён ли SecureBoot. Если не отключён - использование драйвера невозможно.
	2>nul reg query "HKLM\System\CurrentControlSet\Control\SecureBoot\State" /v "UEFISecureBootEnabled" | find /i "0x1" >nul 2>&1 && (
			%ch% {0c} Включен SecureBoot в BIOS. Драйвер не может быть запущен.{\n #}
			%ch% {08} 1. Выполнените удаление несколько раз [цифра 1]{\n #}
			%ch% {08} 2. Перезапустите ПК.{\n #}
			%ch% {08} Если после этого что-то будет {0c}красное {08}в гл. меню - выключите SecureBoot в BIOS{\n #}
			%ch% {08} и повторите удаление.{\n #}
			%ch% {08} Если все зеленое в гл. в меню и в пункте 2 - использовать драйвер не требуется.{\n #}{\n #}
			call :Pause && goto Start
	)
	call :NullVar inputdrv
	%ch% {0c} Внимательно прочитайте текстовый документ возле .bat перед использованием драйвера.{\n#}
	%ch% {0c} Если Вы ознакомились с readme и желаете продолжить - напишите {0b}Yes{\n#}
	%ch% {0c} Если Вы не поняли для чего использовать драйвер - не делайте этого и нажмите здесь Enter.{\n#}{\n#}
	%ch% {0c} Если нет резервной копии - восстановление невозможно{\n#}{\n#}
	
	%ch% {08} Введите {0b}Yes {08}для продолжения{\n#}
	set /p inputdrv=
	if not defined inputdrv (
		%ch% {0c} Пустой ввод, отмена и возврат в главное меню{\n#}
		call :Pause
		goto Start
	)
	if /i not "%inputdrv%"=="Yes" (
		%ch% {0c} Неккоретный ввод, должно быть - Yes{\n#}
		timeout /t 3 >nul
		cls && goto UseKernelDrv
	)
	
	7z x -aoa -bso0 -bsp1 "DKT.zip" -p"DDK" "iamdrvd77hello.sys" >nul
	sc create dkkddkkk type= kernel binPath= "%~dp0Work\iamdrvd77hello.sys" >nul 2>&1
	net start dkkddkkk
	timeout /t 2 /nobreak >nul
	sc stop dkkddkkk >nul 2>&1
	net start dkkddkkk
	sc stop dkkddkkk >nul 2>&1
	sc delete dkkddkkk >nul 2>&1
	del /q iamdrvd77hello.sys >nul 2>&1
	call :Pause && goto Start

:VBSDis
rem Отключение VBS
	bcdedit /set hypervisorlaunchtype off >nul
	for %%p in (
		HypervisorEnforcedCodeIntegrity
		LsaCfgFlags
		RequirePlatformSecurityFeatures
		ConfigureSystemGuardLaunch
		ConfigureKernelShadowStacksLaunch
	) do reg delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "%%p" /f >nul 2>&1
	for %%p in (
		EnableVirtualizationBasedSecurity
		HVCIMATRequired
	) do reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
	for %%p in (
		WasEnabledBy
		WasEnabledBySysprep
	) do reg delete "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "%%p" /f >nul 2>&1
	for %%p in (
		Enabled
		HVCIMATRequired
		Locked
	) do reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
	for %%p in (
		EnableVirtualizationBasedSecurity
		RequirePlatformSecurityFeatures
		Locked
	) do reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
	for %%p in (
		Enabled
		AuditModeEnabled
		WasEnabledBy
	) do reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
	%ch% {0a} Готово. Перезапустите ПК.{\n#}
	call :Pause && goto ManageDefender
:Pause
    %ch% {\n}{08} Для продолжения нажмите любую клавишу...{\n #}& pause >nul & exit /b
:NullVar
	for %%a in (%*) do set "%%a=" 2>nul
	exit /b