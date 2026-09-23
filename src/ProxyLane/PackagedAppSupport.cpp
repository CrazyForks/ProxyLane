#include "stdafx.h"
#include "PackagedAppSupport.h"

#include <aclapi.h>
#include <sddl.h>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")

namespace
{
	typedef LONG (WINAPI *pfnPackageFamilyNameFromFullName)(
		PCWSTR packageFullName,
		UINT32 *packageFamilyNameLength,
		PWSTR packageFamilyName);

	static const GUID CLSID_AppActivationMgr =
		{ 0x45ba127d, 0x10a8, 0x46ea, { 0x8a, 0xb7, 0x56, 0xea, 0x90, 0x78, 0x94, 0x3c } };

	static const GUID IID_IAppActivationMgr =
		{ 0x2e941141, 0x7f97, 0x4756, { 0xba, 0x1d, 0x9d, 0xec, 0xde, 0x89, 0x4a, 0x3d } };

	MIDL_INTERFACE("2E941141-7F97-4756-BA1D-9DECDE894A3D")
	IProxyLaneAppActivationManager : public IUnknown
	{
	public:
		virtual HRESULT STDMETHODCALLTYPE ActivateApplication(
			LPCWSTR appUserModelId,
			LPCWSTR arguments,
			DWORD options,
			DWORD *processId) = 0;
		virtual HRESULT STDMETHODCALLTYPE ActivateForFile(
			LPCWSTR appUserModelId,
			PVOID itemArray,
			LPCWSTR verb,
			DWORD *processId) = 0;
		virtual HRESULT STDMETHODCALLTYPE ActivateForProtocol(
			LPCWSTR appUserModelId,
			PVOID itemArray,
			DWORD *processId) = 0;
	};

	CString ExtractXmlAttribute(const CString& tag, LPCTSTR attrName)
	{
		CString search;
		search.Format(_T("%s="), attrName);
		int pos = tag.Find(search);
		if (pos == -1)
			return CString();

		pos += search.GetLength();
		if (pos >= tag.GetLength())
			return CString();

		TCHAR quote = tag[pos];
		if (quote != _T('"') && quote != _T('\''))
			return CString();

		int endQuote = tag.Find(quote, pos + 1);
		if (endQuote == -1)
			return CString();

		return tag.Mid(pos + 1, endQuote - pos - 1);
	}

	CString NormalizePathSeparators(const CString& path)
	{
		CString result = path;
		result.Replace(_T('/'), _T('\\'));
		result.Trim(_T(" \\/\"'"));
		return result;
	}
}

BOOL PackagedAppSupport::EnsureAppContainerAccess(LPCTSTR folderPath)
{
	if (!folderPath || !folderPath[0])
		return FALSE;

	// 解析 S-1-15-2-1 (ALL APPLICATION PACKAGES)
	PSID pAppPackageSid = NULL;
	if (!ConvertStringSidToSidW(L"S-1-15-2-1", &pAppPackageSid))
	{
		// Windows 7 / XP 不支持该 SID，直接跳过
		return TRUE;
	}

	PACL pOldDacl = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	BOOL bResult = TRUE;

	DWORD dwErr = GetNamedSecurityInfo(
		const_cast<LPTSTR>(folderPath),
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDacl, NULL, &pSD);

	if (dwErr == ERROR_SUCCESS && pOldDacl)
	{
		BOOL bAlreadyGranted = FALSE;
		ACL_SIZE_INFORMATION aclSizeInfo = { 0 };
		if (GetAclInformation(pOldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation))
		{
			for (DWORD i = 0; i < aclSizeInfo.AceCount; ++i)
			{
				LPVOID pAce = NULL;
				if (GetAce(pOldDacl, i, &pAce))
				{
					PACE_HEADER pAceHeader = reinterpret_cast<PACE_HEADER>(pAce);
					if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
					{
						ACCESS_ALLOWED_ACE* pAllowed = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAce);
						if (EqualSid(reinterpret_cast<PSID>(&pAllowed->SidStart), pAppPackageSid))
						{
							const DWORD REQUIRED_ACCESS = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
							if ((pAllowed->Mask & REQUIRED_ACCESS) == REQUIRED_ACCESS)
							{
								bAlreadyGranted = TRUE;
								break;
							}
						}
					}
				}
			}
		}

		if (!bAlreadyGranted)
		{
			EXPLICIT_ACCESS ea = { 0 };
			ea.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
			ea.grfAccessMode = GRANT_ACCESS;
			ea.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
			ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ea.Trustee.ptstrName = reinterpret_cast<LPTSTR>(pAppPackageSid);

			PACL pNewDacl = NULL;
			dwErr = SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl);
			if (dwErr == ERROR_SUCCESS && pNewDacl)
			{
				dwErr = SetNamedSecurityInfo(
					const_cast<LPTSTR>(folderPath),
					SE_FILE_OBJECT,
					DACL_SECURITY_INFORMATION,
					NULL, NULL, pNewDacl, NULL);
				bResult = (dwErr == ERROR_SUCCESS);
				LocalFree(pNewDacl);
			}
			else
			{
				bResult = FALSE;
			}
		}
	}

	if (pSD)
		LocalFree(pSD);
	if (pAppPackageSid)
		LocalFree(pAppPackageSid);

	return bResult;
}

BOOL PackagedAppSupport::FindManifestDir(LPCTSTR filePath, CString& outManifestDir)
{
	outManifestDir.Empty();
	if (!filePath || !filePath[0])
		return FALSE;

	CString normalized(filePath);
	normalized.Trim(_T(" \"'"));

	// 向上寻找 AppxManifest.xml（最多递归 6 层目录）
	int lastSlash = max(normalized.ReverseFind(_T('\\')), normalized.ReverseFind(_T('/')));
	if (lastSlash < 0)
		return FALSE;

	CString currentDir = normalized.Left(lastSlash);
	for (int depth = 0; depth < 6 && !currentDir.IsEmpty(); ++depth)
	{
		CString manifestCandidate = currentDir + _T("\\AppxManifest.xml");
		DWORD attrs = GetFileAttributes(manifestCandidate);
		if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
		{
			outManifestDir = currentDir;
			return TRUE;
		}

		int parentSlash = max(currentDir.ReverseFind(_T('\\')), currentDir.ReverseFind(_T('/')));
		if (parentSlash <= 0)
			break;
		currentDir = currentDir.Left(parentSlash);
	}

	return FALSE;
}

BOOL PackagedAppSupport::IsPackagedAppPath(LPCTSTR filePath, CString& outManifestDir)
{
	outManifestDir.Empty();
	if (!filePath || !filePath[0])
		return FALSE;

	CString lower(filePath);
	lower.MakeLower();
	BOOL inWindowsApps = (lower.Find(_T("\\windowsapps\\")) != -1);

	// 仅当确实位于 WindowsApps 且能定位到 AppxManifest.xml 时才认定为安装的商店包
	if (!inWindowsApps)
		return FALSE;

	return FindManifestDir(filePath, outManifestDir);
}

BOOL PackagedAppSupport::ResolvePackagedAppAumid(
	LPCTSTR targetExePath,
	const CString& manifestDir,
	CString& outAumid,
	CString& outPackageFullName)
{
	outAumid.Empty();
	outPackageFullName.Empty();

	if (!targetExePath || !targetExePath[0] || manifestDir.IsEmpty())
		return FALSE;

	// 1. 从 manifestDir 提取包全名 PackageFullName
	int slash = max(manifestDir.ReverseFind(_T('\\')), manifestDir.ReverseFind(_T('/')));
	if (slash >= 0)
		outPackageFullName = manifestDir.Mid(slash + 1);
	else
		outPackageFullName = manifestDir;

	if (outPackageFullName.IsEmpty())
		return FALSE;

	// 2. 动态加载 PackageFamilyNameFromFullName
	CString familyName;
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32)
	{
		pfnPackageFamilyNameFromFullName pfnPfn =
			reinterpret_cast<pfnPackageFamilyNameFromFullName>(
				GetProcAddress(hKernel32, "PackageFamilyNameFromFullName"));
		if (pfnPfn)
		{
			UINT32 len = 0;
#ifdef UNICODE
			LPCWSTR pkgFullNameW = outPackageFullName;
#else
			CStringW pkgFullNameW(outPackageFullName);
#endif
			if (pfnPfn(pkgFullNameW, &len, NULL) == ERROR_INSUFFICIENT_BUFFER && len > 0)
			{
				std::vector<WCHAR> buffer(len);
				if (pfnPfn(pkgFullNameW, &len, &buffer[0]) == ERROR_SUCCESS)
				{
					familyName = CString(&buffer[0]);
				}
			}
		}
	}

	// 3. 读取 AppxManifest.xml 解析目标应用程序的 Application Id
	CString manifestPath = manifestDir + _T("\\AppxManifest.xml");
	HANDLE hFile = CreateFile(
		manifestPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > 10 * 1024 * 1024)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	std::vector<char> rawData(fileSize + 1, 0);
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, &rawData[0], fileSize, &bytesRead, NULL) || bytesRead == 0)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	CloseHandle(hFile);
	rawData[bytesRead] = '\0';

	// 将 UTF-8 转换为宽字符
	int wideLen = MultiByteToWideChar(CP_UTF8, 0, &rawData[0], bytesRead, NULL, 0);
	if (wideLen <= 0)
		return FALSE;

	std::vector<WCHAR> wideBuffer(wideLen + 1, 0);
	MultiByteToWideChar(CP_UTF8, 0, &rawData[0], bytesRead, &wideBuffer[0], wideLen);
	CString xmlContent(&wideBuffer[0]);

	// 计算目标可执行文件相对于 manifestDir 的相对路径
	CString normTarget = NormalizePathSeparators(targetExePath);
	CString normManifest = NormalizePathSeparators(manifestDir);
	CString relExe;
	if (normTarget.GetLength() > normManifest.GetLength() &&
		normTarget.Left(normManifest.GetLength()).CompareNoCase(normManifest) == 0)
	{
		relExe = normTarget.Mid(normManifest.GetLength());
		relExe.Trim(_T("\\/ "));
	}

	// 扫描 <Application 标签
	CString matchedAppId;
	CString firstAppId;
	int searchPos = 0;
	while (true)
	{
		int appStart = xmlContent.Find(_T("<Application"), searchPos);
		if (appStart == -1)
			break;

		int appEnd = xmlContent.Find(_T('>'), appStart);
		if (appEnd == -1)
			break;

		CString tag = xmlContent.Mid(appStart, appEnd - appStart + 1);
		CString id = ExtractXmlAttribute(tag, _T("Id"));
		CString exe = ExtractXmlAttribute(tag, _T("Executable"));

		if (!id.IsEmpty())
		{
			if (firstAppId.IsEmpty())
				firstAppId = id;

			if (!relExe.IsEmpty() && !exe.IsEmpty())
			{
				CString normExe = NormalizePathSeparators(exe);
				if (normExe.CompareNoCase(relExe) == 0)
				{
					matchedAppId = id;
					break;
				}
			}
		}

		searchPos = appEnd + 1;
	}

	CString selectedAppId = !matchedAppId.IsEmpty() ? matchedAppId : firstAppId;
	if (selectedAppId.IsEmpty())
		selectedAppId = _T("App"); // 通用默认应用标识

	// 若尚未能解析出 familyName，尝试从 PackageFullName 中截取前缀做兜底
	if (familyName.IsEmpty())
	{
		int firstUnder = outPackageFullName.Find(_T('_'));
		int lastUnder = outPackageFullName.ReverseFind(_T('_'));
		if (firstUnder != -1 && lastUnder > firstUnder)
		{
			familyName = outPackageFullName.Left(firstUnder) + outPackageFullName.Mid(lastUnder);
		}
		else
		{
			familyName = outPackageFullName;
		}
	}

	outAumid = familyName + _T("!") + selectedAppId;
	return TRUE;
}

HRESULT PackagedAppSupport::ActivatePackagedApp(
	LPCTSTR aumid,
	LPCTSTR arguments,
	DWORD* outProcessId)
{
	if (!aumid || !aumid[0] || !outProcessId)
		return E_INVALIDARG;

	*outProcessId = 0;

	// 初始化 COM
	HRESULT hrCo = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	IProxyLaneAppActivationManager* pAAM = NULL;
	HRESULT hr = CoCreateInstance(
		CLSID_AppActivationMgr,
		NULL,
		CLSCTX_LOCAL_SERVER,
		IID_IAppActivationMgr,
		reinterpret_cast<LPVOID*>(&pAAM));

	if (SUCCEEDED(hr) && pAAM)
	{
#ifdef UNICODE
		LPCWSTR aumidW = aumid;
		LPCWSTR argsW = (arguments && arguments[0]) ? arguments : NULL;
#else
		CStringW aumidW(aumid);
		CStringW argsW(arguments ? arguments : _T(""));
		LPCWSTR pArgs = (arguments && arguments[0]) ? static_cast<LPCWSTR>(argsW) : NULL;
#endif
		DWORD pid = 0;
		hr = pAAM->ActivateApplication(aumidW, argsW, 0, &pid);
		if (SUCCEEDED(hr))
		{
			*outProcessId = pid;
		}
		pAAM->Release();
	}

	if (SUCCEEDED(hrCo))
		CoUninitialize();

	return hr;
}
