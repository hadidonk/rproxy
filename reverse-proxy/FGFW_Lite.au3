﻿#-*- coding: UTF-8 -*-
#NoTrayIcon
#region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=taskbar.ico
#endregion ;**** Directives created by AutoIt3Wrapper_GUI ****

#include <Misc.au3>
#include <Constants.au3>
#include <WinAPI.au3>

_Singleton(@ScriptName, 0)
setEnv()
OnAutoItExitRegister("onExit")
Global $SUB_PID = -1
setTray()
startSetAutorun()
startSetProxy()
daemon()
Exit

Func setEnv()
	If StringInStr(@ScriptDir, " ") Then
		MsgBox(16, "FGFW_Lite", "路径中不允许有空格，FGFW_Lite将退出！", 5)
		Exit (1)
	EndIf
EndFunc   ;==>setEnv

Func setTray()

	Opt("TrayAutoPause", 0)
	Opt("TrayOnEventMode", 1)
	Opt("TrayMenuMode", 3)

	TrayCreateItem("显示/隐藏 Console")
	TrayItemSetOnEvent(-1, "showHideConsole")

	$trayMenuSetProxy = TrayCreateMenu("设置代理")

	TrayCreateItem("智能代理8118", $trayMenuSetProxy)
	TrayItemSetOnEvent(-1, "setProxyAuto")

	TrayCreateItem("全局代理8119", $trayMenuSetProxy)
	TrayItemSetOnEvent(-1, "setProxyOverall")

	TrayCreateItem("直接连接", $trayMenuSetProxy)
	TrayItemSetOnEvent(-1, "setProxyDirect")

	$trayMenuAdvanced = TrayCreateMenu("高级")

	TrayCreateItem("清除DNS缓存", $trayMenuAdvanced)
	TrayItemSetOnEvent(-1, "flushDNS")

	TrayCreateItem("网址提交", $trayMenuAdvanced)
	TrayItemSetOnEvent(-1, "ifGFWed")

	TrayCreateItem("设置开机启动", $trayMenuAdvanced)
	TrayItemSetOnEvent(-1, "setAutorun")

	$trayMenuLConf = TrayCreateMenu("修改配置文件")
	TrayCreateItem("userconf.ini", $trayMenuLConf)
	TrayItemSetOnEvent(-1, "editUserconf")
	TrayCreateItem("local.txt", $trayMenuLConf)
	TrayItemSetOnEvent(-1, "editLocal")

	TrayCreateItem("")

	TrayCreateItem("Exit")
	TrayItemSetOnEvent(-1, "ExitScript")

	TraySetOnEvent($TRAY_EVENT_PRIMARYDOUBLE, "showHideConsole")
	TraySetOnEvent($TRAY_EVENT_PRIMARYUP, "showHideConsole")
	TraySetState()
	TraySetToolTip("FGFW_Lite An uncensored Internet is a better Internet.")
	TraySetClick(16)

EndFunc   ;==>setTray

Func showHideConsole()
	Dim $SUB_PID
	_showHidePID($SUB_PID)
EndFunc   ;==>showHideConsole

Func setProxyOverall()
	_setIEProxy(1, "127.0.0.1:8119", "<local>")
EndFunc   ;==>setProxyOverall

Func setProxyAuto()
	_setIEProxy()
EndFunc   ;==>setProxyAuto

Func setProxyDirect()
	_setIEProxy(0)
EndFunc   ;==>setProxyDirect

Func editUserconf()
	ShellExecute(@ScriptDir & "\userconf.ini")
EndFunc   ;==>viewLog

Func editLocal()
	ShellExecute(@ScriptDir & "\fgfw-lite\local.txt")
EndFunc   ;==>viewLog

Func flushDNS()
	Run("ipconfig.exe /flushdns")
EndFunc   ;==>flushDNS

Func ifGFWed()
	ShellExecute("https://gfwlist.autoproxy.org/report/")
EndFunc   ;==>ifGFWed

Func ExitScript()
	Exit
EndFunc   ;==>ExitScript

Func _showHidePID($PID)
	If Not ProcessExists($PID) Then Return
	$WinHandle = _GetHwndFromPID($PID)
	If _WinAPI_IsWindowVisible($WinHandle) Then
		_WinAPI_ShowWindow($WinHandle, @SW_HIDE)
	Else
		_WinAPI_ShowWindow($WinHandle, @SW_SHOWNORMAL)
		$txt = _WinAPI_GetWindowText($WinHandle)
		If Not WinActive($txt) Then
			WinActivate($txt)
		EndIf
	EndIf
EndFunc   ;==>_showHidePID

Func _GetHwndFromPID($PID)
	$hWnd = 0
	$stPID = DllStructCreate("int")
	Do
		$winlist2 = WinList()
		For $i = 1 To $winlist2[0][0]
			If $winlist2[$i][0] <> "" Then
				DllCall("user32.dll", "int", "GetWindowThreadProcessId", "hwnd", $winlist2[$i][1], "ptr", DllStructGetPtr($stPID))
				If DllStructGetData($stPID, 1) = $PID Then
					$hWnd = $winlist2[$i][1]
					ExitLoop
				EndIf
			EndIf
		Next
		Sleep(100)
	Until $hWnd <> 0
	Return $hWnd
EndFunc   ;==>_GetHwndFromPID


Func setAutorun()
	Local $autoRun = 1
	Local $foo = MsgBox(4, "FGFW_Lite", "开机自动启动？")
	If $foo = 6 Then
		$autoRun = 1
		FileCreateShortcut(@ScriptDir & "\FGFW_Lite.exe", @StartupDir & "\FGFW_Lite.lnk", @ScriptDir)
	Else
		$autoRun = 0
		FileDelete(@StartupDir & "\FGFW_Lite.lnk")
	EndIf
	IniWrite("userconf.ini", "FGFW_Lite", "autoRun", $autoRun)

EndFunc   ;==>setAutorun


Func startSetAutorun()
	Local $autoRun = _GetConf("FGFW_Lite", "autoRun", "2")
	If $autoRun = 2 Then setAutorun()
	If $autoRun = 1 Then FileCreateShortcut(@ScriptDir & "\FGFW_Lite.exe", @StartupDir & "\FGFW_Lite.lnk", @ScriptDir)
	If $autoRun = 0 Then FileDelete(@StartupDir & "\FGFW_Lite.lnk")
EndFunc   ;==>startSetAutorun


Func startSetProxy()
	Local $setIEProxy = _GetConf("FGFW_Lite", "setIEProxy", "1")
	If $setIEProxy = 1 Then
		If IniRead("userconf.ini", "Proxy", "ProxyEnable", "10") = 10 Then
			Local $ifproxy = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable")
			Local $proxy = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer")
			Local $override = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyOverride")
			IniWrite("userconf.ini", "Proxy", "ProxyEnable", $ifproxy)
			IniWrite("userconf.ini", "Proxy", "ProxyServer", $proxy)
			IniWrite("userconf.ini", "Proxy", "ProxyOverride", $override)
			setProxyAuto()
		EndIf
	EndIf
EndFunc   ;==>startSetProxy

Func daemon()
	Dim $SUB_PID
	$SILENT = 1
	While True
		Sleep(3000)
		$SUB_PID = Run("./Python27/python27.exe -B ./fgfw-lite/fgfw-lite.py -hide", @ScriptDir, @SW_HIDE)
		If Not $SILENT Then TrayTip("FGFW_Lite", 'FGFW_Lite Restarting...', 0)
		While ProcessExists($SUB_PID)
			Sleep(300)
		WEnd
		$SILENT = 0
	WEnd
EndFunc   ;==>daemon

Func onExit()
	$hWnd = _GetHwndFromPID($SUB_PID)
	$title = _WinAPI_GetWindowText($hWnd)
	WinClose($title)
	Local $ifproxy = IniRead("userconf.ini", "Proxy", "ProxyEnable", "0")
	Local $proxy = IniRead("userconf.ini", "Proxy", "ProxyServer", "")
	Local $override = IniRead("userconf.ini", "Proxy", "ProxyOverride", "")
	_setIEProxy($ifproxy, $proxy, $override)
	IniDelete("userconf.ini", "Proxy", "ProxyEnable")
	IniDelete("userconf.ini", "Proxy", "ProxyServer")
	IniDelete("userconf.ini", "Proxy", "ProxyOverride")
EndFunc   ;==>onExit

Func _setIEProxy($ProxyEnable = 1, $ProxyServer = "127.0.0.1:8118", $ProxyOverride = "<local>")
	RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable", "REG_DWORD", $ProxyEnable)
	If $ProxyEnable = 0 Then
		RegDelete("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer")
		RegDelete("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyOverride")
	Else
		RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer", "REG_SZ", $ProxyServer)
		RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyOverride", "REG_SZ", $ProxyOverride)
	EndIf
	DllCall('WININET.DLL', 'long', 'InternetSetOption', 'int', 0, 'long', 39, 'str', 0, 'long', 0)
EndFunc   ;==>_setIEProxy

Func _GetConf($section, $key, $default)
	Local $value2 = IniRead("userconf.ini", $section, $key, $default)
	Return $value2
EndFunc   ;==>_GetConf