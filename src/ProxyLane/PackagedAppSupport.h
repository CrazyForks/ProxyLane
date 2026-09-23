#pragma once

#include <afxstr.h>
#include <windows.h>

namespace PackagedAppSupport
{
	// 检查并确保指定目录对 ALL APPLICATION PACKAGES (S-1-15-2-1) 授予读取和执行权限
	BOOL EnsureAppContainerAccess(LPCTSTR folderPath);

	// 向上查找包含 AppxManifest.xml 的目录
	BOOL FindManifestDir(LPCTSTR filePath, CString& outManifestDir);

	// 检测目标路径是否位于包含 AppxManifest.xml 的 WindowsApps 目录中
	BOOL IsPackagedAppPath(LPCTSTR filePath, CString& outManifestDir);

	// 解析包的 PackageFullName 与 AUMID (AppUserModelId)
	BOOL ResolvePackagedAppAumid(
		LPCTSTR targetExePath,
		const CString& manifestDir,
		CString& outAumid,
		CString& outPackageFullName);

	// 激活打包应用并获取目标进程 PID
	HRESULT ActivatePackagedApp(
		LPCTSTR aumid,
		LPCTSTR arguments,
		DWORD* outProcessId);
}
