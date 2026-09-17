// ProxyLaneDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "ProxyLaneDlg.h"
#include "AppVersion.h"
#include "Localization.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define _MUTEX _T("{BAD09968-F0A9-4818-AD34-B39DFDA840FE}")

#define WM_SHELLICON_NOTIFY				(WM_APP+100)
#define WM_AUTOMATION_START				(WM_APP+101)
UINT s_uTaskbarRestart = -1;

namespace
{
	enum TaskbarMenuCommand
	{
		TASKBAR_MENU_OPEN = 1,
		TASKBAR_MENU_STOP_PROXY,
		TASKBAR_MENU_EXIT,
		TASKBAR_MENU_PROFILE_FIRST = 1000
	};

	HICON CreateGrayscaleIcon(HICON sourceIcon)
	{
		if (!sourceIcon)
			return NULL;

		ICONINFO sourceInfo = { 0 };
		if (!GetIconInfo(sourceIcon, &sourceInfo) || !sourceInfo.hbmColor)
		{
			if (sourceInfo.hbmColor)
				DeleteObject(sourceInfo.hbmColor);
			if (sourceInfo.hbmMask)
				DeleteObject(sourceInfo.hbmMask);
			return CopyIcon(sourceIcon);
		}

		BITMAP bitmap = { 0 };
		GetObject(sourceInfo.hbmColor, sizeof(bitmap), &bitmap);
		BITMAPINFO bitmapInfo = { 0 };
		bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bitmapInfo.bmiHeader.biWidth = bitmap.bmWidth;
		bitmapInfo.bmiHeader.biHeight = bitmap.bmHeight;
		bitmapInfo.bmiHeader.biPlanes = 1;
		bitmapInfo.bmiHeader.biBitCount = 32;
		bitmapInfo.bmiHeader.biCompression = BI_RGB;

		std::vector<DWORD> pixels(bitmap.bmWidth * bitmap.bmHeight);
		HDC screenDc = GetDC(NULL);
		HICON grayIcon = NULL;
		if (screenDc && GetDIBits(screenDc, sourceInfo.hbmColor, 0,
			bitmap.bmHeight, &pixels[0], &bitmapInfo, DIB_RGB_COLORS))
		{
			for (size_t index = 0; index < pixels.size(); ++index)
			{
				const DWORD pixel = pixels[index];
				const BYTE blue = static_cast<BYTE>(pixel & 0xff);
				const BYTE green = static_cast<BYTE>((pixel >> 8) & 0xff);
				const BYTE red = static_cast<BYTE>((pixel >> 16) & 0xff);
				const BYTE alpha = static_cast<BYTE>((pixel >> 24) & 0xff);
				const BYTE gray = static_cast<BYTE>((red * 30 + green * 59 + blue * 11) / 100);
				pixels[index] = (static_cast<DWORD>(alpha) << 24)
					| (static_cast<DWORD>(gray) << 16)
					| (static_cast<DWORD>(gray) << 8)
					| gray;
			}

			HBITMAP grayBitmap = CreateDIBitmap(screenDc, &bitmapInfo.bmiHeader,
				CBM_INIT, &pixels[0], &bitmapInfo, DIB_RGB_COLORS);
			if (grayBitmap)
			{
				ICONINFO grayInfo = sourceInfo;
				grayInfo.hbmColor = grayBitmap;
				grayIcon = CreateIconIndirect(&grayInfo);
				DeleteObject(grayBitmap);
			}
		}
		if (screenDc)
			ReleaseDC(NULL, screenDc);
		DeleteObject(sourceInfo.hbmColor);
		if (sourceInfo.hbmMask)
			DeleteObject(sourceInfo.hbmMask);
		return grayIcon ? grayIcon : CopyIcon(sourceIcon);
	}

	CString EscapeMenuText(const CString& text)
	{
		CString escaped(text);
		escaped.Replace(_T("&"), _T("&&"));
		return escaped;
	}
}

//////////////////////////////////////////////////////////////////////////
// ShellNotifyIcon
BOOL
ShellNotifyIcon_Add(
	HWND hWnd,
	UINT nID,
	UINT nCallbackMessage,
	HICON hIcon,
	PCTSTR szTip,
	UINT nFlags /*= NIF_MESSAGE|NIF_ICON|NIF_TIP*/)
{
	NOTIFYICONDATA tnid = { sizeof(tnid), 0 };
	tnid.hWnd = hWnd;
	tnid.uID = nID;
	tnid.uCallbackMessage = nCallbackMessage;
	tnid.uFlags = nFlags;
	tnid.hIcon = hIcon;
	if(szTip)
	{
		_tcsncpy(
			tnid.szTip,
			szTip,
			_countof(tnid.szTip)-1);
		tnid.szTip[_countof(tnid.szTip)-1] = _T('\0');
	}
	return Shell_NotifyIcon(
		NIM_ADD,
		&tnid);
}

BOOL
ShellNotifyIcon_Delete(
	HWND hWnd,
	UINT nID)
{
	NOTIFYICONDATA tnid = { sizeof(tnid), 0 };
	tnid.hWnd = hWnd;
	tnid.uID = nID;
	return Shell_NotifyIcon(
		NIM_DELETE,
		&tnid);
}

BOOL
ShellNotifyIcon_Modify(
	HWND hWnd,
	UINT nID,
	UINT nCallbackMessage,
	HICON hIcon,
	PCTSTR szTip,
	UINT nFlags)
{
	NOTIFYICONDATA tnid = { sizeof(tnid), 0 };
	tnid.hWnd = hWnd;
	tnid.uID = nID;
	tnid.uCallbackMessage = nCallbackMessage;
	tnid.uFlags = nFlags;
	tnid.hIcon = hIcon;
	if(szTip)
	{
		_tcsncpy(
			tnid.szTip,
			szTip,
			_countof(tnid.szTip)-1);
		tnid.szTip[_countof(tnid.szTip)-1] = _T('\0');
	}
	return Shell_NotifyIcon(
		NIM_MODIFY,
		&tnid);
}

BOOL
ShellNotifyIcon_AddInfo(
						HWND hWnd, 
						UINT nID, 
						UINT nCallbackMessage, 
						HICON hIcon, 
						PCTSTR szInfo, 
						UINT nFlags)
{
	NOTIFYICONDATA tnid = { sizeof(tnid), 0 };
	tnid.hWnd = hWnd;
	tnid.uID = nID;
	tnid.uCallbackMessage = nCallbackMessage;
	tnid.uFlags = nFlags;
	tnid.hIcon = hIcon;
	if(szInfo)
	{
		_tcsncpy(
			tnid.szInfo,
			szInfo,
			_countof(tnid.szInfo)-1);
		tnid.szInfo[_countof(tnid.szInfo)-1] = _T('\0');
	}
	return Shell_NotifyIcon(
		NIM_ADD,
		&tnid);
}


// CProxyLaneDlg 对话框




CProxyLaneDlg::CProxyLaneDlg(CWnd* pParent /*=NULL*/)
	: CModernDialog(CProxyLaneDlg::IDD, pParent)
	, m_hInactiveIcon(NULL)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProxyLaneDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CProxyLaneDlg, CModernDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_SHELLICON_NOTIFY, OnShellIconNotify)
	ON_REGISTERED_MESSAGE(s_uTaskbarRestart, OnTaskbarRestartNotify)
	ON_MESSAGE(WM_AUTOMATION_START, OnAutomationStart)
	ON_MESSAGE(WM_PROXY_STATUS_CHANGED, OnProxyStatusChanged)
	ON_MESSAGE(WM_PROFILE_COMMAND_REQUEST, OnProfileCommandRequest)
	//}}AFX_MSG_MAP
	ON_WM_DESTROY()
	ON_WM_SIZE()
	ON_WM_GETMINMAXINFO()
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


// CProxyLaneDlg 消息处理程序

BOOL CProxyLaneDlg::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	// Do not expose a half-initialized child-dialog tree. On a busy machine
	// Windows can otherwise compose individual controls before page creation,
	// localization and profile loading have all completed.
	ShowWindow(SW_HIDE);
	SetRedraw(FALSE);

	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标
	m_hInactiveIcon = CreateGrayscaleIcon(GetIcon(FALSE));

	// TODO: 在此添加额外的初始化代码

	//HANDLE hMutex = CreateMutex(0, 0, _MUTEX);
	//if(hMutex && GetLastError() == ERROR_ALREADY_EXISTS)
	//{
	//	MessageBox(_T("已经在运行中……"));
	//	OnOK();
	//	return FALSE;
	//}

	if (!m_MainTab.CreateTabCtrl(this))
	{
		SetRedraw(TRUE);
		EndDialog(IDCANCEL);
		return FALSE;
	}
	DragAcceptFiles(TRUE);

	SetWindowText(AppVersion::DisplayTitle());

	s_uTaskbarRestart = RegisterWindowMessage(TEXT("TaskbarCreated"));

	AddTaskbarIcons();
	m_MainTab.FinalizeLayout(FALSE);
	SetRedraw(TRUE);

	if (theApp.GetAutomationOptions().enabled)
	{
		ShowWindow(SW_HIDE);
		PostMessage(WM_AUTOMATION_START);
	}
	else
	{
		ShowWindow(SW_SHOW);
		RedrawWindow(NULL, NULL,
			RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CProxyLaneDlg::OnCancel()
{
	CPage1* page1 = m_MainTab.GetPage1();
	if (page1 && !theApp.GetAutomationOptions().enabled
		&& !page1->ConfirmDiscardUnsavedChanges())
	{
		return;
	}
	CModernDialog::OnCancel();
}

void CProxyLaneDlg::FailAutomation(int exitCode)
{
	theApp.SetAutomationExitCode(exitCode);
	CPage1 *page1 = m_MainTab.GetPage1();
	if (page1)
		page1->StopProxy();
	EndDialog(IDCANCEL);
}

LRESULT CProxyLaneDlg::OnAutomationStart(WPARAM wParam, LPARAM lParam)
{
	const AutomationOptions& options = theApp.GetAutomationOptions();
	if (!options.enabled)
		return 0;

	CPage1 *page1 = m_MainTab.GetPage1();
	CPage3 *page3 = m_MainTab.GetPage3();
	if (!page1 || !page3)
	{
		FailAutomation(AUTOMATION_EXIT_PROXY_START_FAILED);
		return 0;
	}

	if (!page1->LoadProfileByName(options.profileName))
	{
		FailAutomation(AUTOMATION_EXIT_PROFILE_INVALID);
		return 0;
	}

	if (!page1->StartProxy(FALSE))
	{
		FailAutomation(AUTOMATION_EXIT_PROXY_START_FAILED);
		return 0;
	}
	if (!RefreshProfileCommandServer() && theApp.RequiresProfileCommandOwnership())
	{
		FailAutomation(AUTOMATION_EXIT_COMMAND_FORWARD_FAILED);
		return 0;
	}

	AppLaunchResult launchResult = page3->LaunchAndProxyApp(
		options.targetPath,
		options.targetArguments,
		TRUE);
	if (launchResult != APP_LAUNCH_SUCCESS)
	{
		int exitCode = AUTOMATION_EXIT_TARGET_INVALID;
		if (launchResult == APP_LAUNCH_CREATE_PROCESS_FAILED)
			exitCode = AUTOMATION_EXIT_CREATE_PROCESS_FAILED;
		else if (launchResult == APP_LAUNCH_UAC_CANCELLED ||
			launchResult == APP_LAUNCH_ELEVATED_HELPER_FAILED)
			exitCode = AUTOMATION_EXIT_CREATE_PROCESS_FAILED;
		else if (launchResult == APP_LAUNCH_INJECTION_FAILED)
			exitCode = AUTOMATION_EXIT_INJECTION_FAILED;
		FailAutomation(exitCode);
		return 0;
	}

	theApp.SignalAutomationReady();
	return 0;
}

BOOL CProxyLaneDlg::RefreshProfileCommandServer()
{
	if (!m_MainTab.IsProxyRunning())
	{
		theApp.DeactivateProfileCommandServer();
		return TRUE;
	}

	CString profileName = m_MainTab.GetRunningProfileName();
	return theApp.ActivateProfileCommandServer(profileName, GetSafeHwnd());
}

BOOL CProxyLaneDlg::AddTaskbarIcons()
{
	const CString tooltip = BuildTaskbarTooltip();
	return ShellNotifyIcon_Add(
		m_hWnd,
		IDD,
		WM_SHELLICON_NOTIFY,
		GetTaskbarIcon(),
		tooltip);
}

CString CProxyLaneDlg::BuildTaskbarTooltip() const
{
	CString tooltip = AppVersion::DisplayTitle();
	if (m_MainTab.IsProxyRunning())
	{
		tooltip += Localization::Format(_T("dialog.running_suffix"),
			static_cast<LPCTSTR>(m_MainTab.GetRunningProfileName()));
	}
	else
	{
		tooltip += Localization::Get(_T("dialog.stopped_suffix"));
	}
	return tooltip;
}

HICON CProxyLaneDlg::GetTaskbarIcon() const
{
	return m_MainTab.IsProxyRunning() || !m_hInactiveIcon
		? GetIcon(FALSE) : m_hInactiveIcon;
}

void CProxyLaneDlg::UpdateTaskbarIcon()
{
	const CString tooltip = BuildTaskbarTooltip();
	ShellNotifyIcon_Modify(
		m_hWnd,
		IDD,
		WM_SHELLICON_NOTIFY,
		GetTaskbarIcon(),
		tooltip,
		NIF_ICON | NIF_TIP);
}

LRESULT CProxyLaneDlg::OnProxyStatusChanged(WPARAM, LPARAM)
{
	RefreshProfileCommandServer();
	UpdateTaskbarIcon();
	return 0;
}

LRESULT CProxyLaneDlg::OnProfileCommandRequest(WPARAM, LPARAM lParam)
{
	CProfileCommandRequest* request = reinterpret_cast<CProfileCommandRequest*>(lParam);
	if (!request)
		return 0;

	int exitCode = AUTOMATION_EXIT_COMMAND_FORWARD_FAILED;
	if (!InterlockedCompareExchange(&request->cancelled, FALSE, FALSE) &&
		m_MainTab.IsProxyRunning() &&
		m_MainTab.GetRunningProfileName().CompareNoCase(request->profileName) == 0 &&
		theApp.IsProfileCommandServerActive(request->profileName))
	{
		CPage3* page3 = m_MainTab.GetPage3();
		if (page3)
		{
			AppLaunchResult result = page3->LaunchAndProxyApp(
				request->targetPath,
				request->targetArguments,
				TRUE);
			switch (result)
			{
			case APP_LAUNCH_SUCCESS:
				exitCode = AUTOMATION_EXIT_SUCCESS;
				break;
			case APP_LAUNCH_INVALID_TARGET:
				exitCode = AUTOMATION_EXIT_TARGET_INVALID;
				break;
			case APP_LAUNCH_INJECTION_FAILED:
				exitCode = AUTOMATION_EXIT_INJECTION_FAILED;
				break;
			default:
				exitCode = AUTOMATION_EXIT_CREATE_PROCESS_FAILED;
				break;
			}
		}
	}

	request->exitCode = exitCode;
	if (request->completedEvent)
		SetEvent(request->completedEvent);
	request->Release();
	return 0;
}

void CProxyLaneDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	switch (nID)
	{
	case SC_MINIMIZE:
		ShowWindow(SW_HIDE);
		break;
	default:
		CModernDialog::OnSysCommand(nID, lParam);
		break;
	}
}
void CProxyLaneDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示。
//
HCURSOR CProxyLaneDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CProxyLaneDlg::OnDestroy()
{
	theApp.DeactivateProfileCommandServer();
	theApp.ReleaseAutomationLaunchGate();
	ShellNotifyIcon_Delete(
		m_hWnd,
		IDD_PROXYLANE_DIALOG);
	if (m_hInactiveIcon)
	{
		DestroyIcon(m_hInactiveIcon);
		m_hInactiveIcon = NULL;
	}
	CDialog::OnDestroy();
}


LRESULT
CProxyLaneDlg::OnTaskbarRestartNotify(
							   WPARAM wParam,
							   LPARAM lParam
							   )
{
	AddTaskbarIcons();
	return 0;
}

LRESULT
CProxyLaneDlg::OnShellIconNotify(
							WPARAM wParam,
							LPARAM lParam
							)
{
	if(wParam == IDD)
	{
		switch(lParam)
		{
		case WM_LBUTTONDBLCLK:
			ShowAndActivate();
			break;
		case WM_RBUTTONUP:
			ShowTaskbarMenu();
			break;
		default:
			break;
		}
	}

	return 1;
}

void CProxyLaneDlg::ShowTaskbarMenu()
{
	CMenu menu;
	if (!menu.CreatePopupMenu())
		return;

	menu.AppendMenu(MF_STRING, TASKBAR_MENU_OPEN,
		Localization::Get(_T("tray.open")));
	menu.AppendMenu(MF_SEPARATOR);

	CPage1* page1 = m_MainTab.GetPage1();
	std::vector<CString> profiles;
	if (m_MainTab.IsProxyRunning())
	{
		CString runningText = Localization::Format(_T("tray.running_profile"),
			static_cast<LPCTSTR>(m_MainTab.GetRunningProfileName()));
		menu.AppendMenu(MF_STRING | MF_DISABLED | MF_GRAYED, 0, runningText);
		menu.AppendMenu(MF_STRING, TASKBAR_MENU_STOP_PROXY,
			Localization::Get(_T("action.stop_proxy")));
	}
	else
	{
		CMenu profileMenu;
		if (profileMenu.CreatePopupMenu())
		{
			if (page1)
				page1->GetSavedProfileNames(profiles);

			if (profiles.empty())
			{
				profileMenu.AppendMenu(MF_STRING | MF_DISABLED | MF_GRAYED, 0,
					Localization::Get(_T("tray.no_profiles")));
			}
			else
			{
				for (size_t index = 0; index < profiles.size(); ++index)
				{
					profileMenu.AppendMenu(MF_STRING,
						TASKBAR_MENU_PROFILE_FIRST + static_cast<UINT>(index),
						EscapeMenuText(profiles[index]));
				}
			}

			menu.AppendMenu(MF_POPUP,
				reinterpret_cast<UINT_PTR>(profileMenu.Detach()),
				Localization::Get(_T("action.start_proxy")));
		}
	}

	menu.AppendMenu(MF_SEPARATOR);
	menu.AppendMenu(MF_STRING, TASKBAR_MENU_EXIT,
		Localization::Get(_T("tray.exit")));

	CPoint cursor;
	GetCursorPos(&cursor);
	SetForegroundWindow();
	const UINT command = TrackPopupMenu(menu.GetSafeHmenu(),
		TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
		cursor.x, cursor.y, 0, m_hWnd, NULL);
	PostMessage(WM_NULL);

	if (command == TASKBAR_MENU_OPEN)
	{
		ShowAndActivate();
	}
	else if (command == TASKBAR_MENU_STOP_PROXY)
	{
		if (page1 && !page1->StopProxy())
			ShowAndActivate();
	}
	else if (command == TASKBAR_MENU_EXIT)
	{
		if (page1 && page1->HasUnsavedProfileChanges())
			ShowAndActivate();
		PostMessage(WM_CLOSE);
	}
	else if (command >= TASKBAR_MENU_PROFILE_FIRST &&
		command < TASKBAR_MENU_PROFILE_FIRST + profiles.size())
	{
		StartProxyFromTaskbarProfile(
			profiles[command - TASKBAR_MENU_PROFILE_FIRST]);
	}
}

void CProxyLaneDlg::StartProxyFromTaskbarProfile(LPCTSTR profileName)
{
	CPage1* page1 = m_MainTab.GetPage1();
	if (!page1)
		return;

	if (page1->HasUnsavedProfileChanges())
	{
		ShowAndActivate();
		if (!page1->ConfirmDiscardUnsavedChanges())
			return;
	}

	if (!page1->LoadProfileByName(profileName, TRUE))
	{
		ShowAndActivate();
		MessageBox(
			Localization::Format(_T("tray.profile_load_failed"), profileName),
			Localization::Get(_T("proxy.start_failed_title")),
			MB_OK | MB_ICONERROR);
		return;
	}

	if (!page1->StartProxy(TRUE))
		ShowAndActivate();
}

void CProxyLaneDlg::ShowAndActivate()
{
	ShowWindow(IsIconic() ? SW_RESTORE : SW_SHOW);

	// Raise the window without leaving it permanently topmost.
	const UINT flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW;
	SetWindowPos(&wndTopMost, 0, 0, 0, 0, flags);
	SetWindowPos(&wndNoTopMost, 0, 0, 0, 0, flags);

	BringWindowToTop();
	SetForegroundWindow();
	SetActiveWindow();
}

void CProxyLaneDlg::OnSize(UINT nType, int cx, int cy)
{
	CModernDialog::OnSize(nType, cx, cy);

	if (m_MainTab.m_hWnd)
	{
		CRect rc;
		GetClientRect(rc);
		m_MainTab.MoveWindow(rc);
	}
}

void CProxyLaneDlg::OnGetMinMaxInfo(MINMAXINFO* minMaxInfo)
{
	CModernDialog::OnGetMinMaxInfo(minMaxInfo);
	minMaxInfo->ptMinTrackSize.x = UiTheme::ScaleForWindow(m_hWnd, 640);
	minMaxInfo->ptMinTrackSize.y = UiTheme::ScaleForWindow(m_hWnd, 440);
}

void CProxyLaneDlg::OnDropFiles(HDROP dropInfo)
{
	CPage1* page1 = m_MainTab.GetPage1();
	CPage3* page3 = m_MainTab.GetPage3();
	if (!page1 || !page3 || !page1->IsProxyRunning())
	{
		DragFinish(dropInfo);
		m_MainTab.ShowTransientStatus(
			Localization::Get(_T("dialog.unsaved_drop")),
			CStatusLabel::TONE_INFO);
		return;
	}

	const UINT fileCount = DragQueryFile(dropInfo, 0xFFFFFFFF, NULL, 0);
	std::vector<CString> noExtraArguments;
	for (UINT index = 0; index < fileCount; ++index)
	{
		const UINT pathLength = DragQueryFile(dropInfo, index, NULL, 0);
		if (pathLength == 0)
			continue;

		std::vector<TCHAR> pathBuffer(pathLength + 1, _T('\0'));
		if (!DragQueryFile(dropInfo, index, &pathBuffer[0], pathLength + 1))
			continue;

		CString path(&pathBuffer[0]);
		const AppLaunchResult result = page3->LaunchAndProxyApp(
			path, noExtraArguments, TRUE);
		if (result == APP_LAUNCH_SUCCESS)
		{
			int slash = max(path.ReverseFind(_T('\\')), path.ReverseFind(_T('/')));
			CString displayName = slash >= 0 ? path.Mid(slash + 1) : path;
			CString status;
			status = Localization::Format(_T("dialog.started_proxy"), static_cast<LPCTSTR>(displayName));
			m_MainTab.ShowTransientStatus(status, CStatusLabel::TONE_SUCCESS);
			continue;
		}

		CString message;
		if (result == APP_LAUNCH_INVALID_TARGET)
			message = Localization::Get(_T("dialog.drop_invalid"));
		else if (result == APP_LAUNCH_UAC_CANCELLED)
			message = Localization::Get(_T("dialog.drop_uac_cancelled"));
		else if (result == APP_LAUNCH_INJECTION_FAILED)
			message = Localization::Get(_T("dialog.drop_inject_failed"));
		else if (result == APP_LAUNCH_ELEVATED_HELPER_FAILED)
			message = Localization::Get(_T("dialog.drop_elevated_failed"));
		else
			message = Localization::Get(_T("dialog.drop_launch_failed"));

		MessageBox(message, Localization::Get(_T("dialog.drop_failed_title")), MB_OK | MB_ICONERROR);
	}

	DragFinish(dropInfo);
}
