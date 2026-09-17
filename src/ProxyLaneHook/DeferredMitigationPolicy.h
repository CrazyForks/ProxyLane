#pragma once

#include <windows.h>

#define PROXYLANE_DEFERRED_CIG_ENV_W L"_PL_DEFERRED_CIG"
#define PROXYLANE_DEFERRED_CIG_ENV_A "_PL_DEFERRED_CIG"

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK \
	(0x00000003ULL << 44)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON \
	(0x00000001ULL << 44)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE \
	(0x00000003ULL << 44)
#endif

namespace DeferredMitigationPolicy
{
#ifndef ProcessSignaturePolicy
#define ProcessSignaturePolicy 8
#endif

#pragma warning(push)
#pragma warning(disable: 4201)
	typedef struct _PL_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD MicrosoftSignedOnly : 1;
				DWORD StoreSignedOnly : 1;
				DWORD MitigationOptIn : 1;
				DWORD AuditMicrosoftSignedOnly : 1;
				DWORD AuditStoreSignedOnly : 1;
				DWORD ReservedFlags : 27;
			};
		};
	} PL_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;
#pragma warning(pop)

	typedef struct _PL_STARTUPINFOEXW {
		STARTUPINFOW StartupInfo;
		PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
	} PL_STARTUPINFOEXW, *LPPL_STARTUPINFOEXW;

	struct CandidateAttributeEntry {
		DWORD_PTR attribute;
		SIZE_T size;
		PVOID value;
	};

	typedef BOOL (WINAPI *PFN_SetProcessMitigationPolicy)(
		int MitigationPolicy,
		PVOID lpBuffer,
		SIZE_T dwLength
	);

	inline BOOL GetDeferredCigFlagsFromEnvironment(DWORD* pFlags = NULL)
	{
		if (pFlags)
			*pFlags = 0;

		WCHAR buffer[16] = { 0 };
		const DWORD length = GetEnvironmentVariableW(
			PROXYLANE_DEFERRED_CIG_ENV_W,
			buffer,
			static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
		if (length == 0 || length >= sizeof(buffer) / sizeof(buffer[0]))
			return FALSE;

		const DWORD flags = static_cast<DWORD>(wcstoul(buffer, NULL, 10));
		if (flags == 0)
			return FALSE;

		if (pFlags)
			*pFlags = flags;
		return TRUE;
	}

	inline BOOL ShouldRestoreCigFromEnvironment()
	{
		return GetDeferredCigFlagsFromEnvironment(NULL);
	}

	inline BOOL ClearDeferredCigEnvironment()
	{
		return SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, NULL);
	}

	// Safely inspect PROC_THREAD_ATTRIBUTE_LIST to locate caller's mitigation policy DWORD64
	inline DWORD64* FindMitigationPolicyEntry(PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, SIZE_T* pSize = NULL)
	{
		if (pSize)
			*pSize = 0;
		if (!lpAttributeList)
			return NULL;

		__try
		{
			const BYTE* listBytes = reinterpret_cast<const BYTE*>(lpAttributeList);
			const DWORD dwMask = *reinterpret_cast<const DWORD*>(listBytes);
			// Bit 7 indicates PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY (1 << 7 == 0x80)
			if ((dwMask & 0x80) == 0)
				return NULL;

			const DWORD count = *reinterpret_cast<const DWORD*>(listBytes + 4);
			if (count == 0 || count > 64)
				return NULL;

#ifdef _WIN64
			const size_t kHeaderSize = 24;
#else
			const size_t kHeaderSize = 20;
#endif
			const size_t kEntrySize = sizeof(CandidateAttributeEntry);

			for (DWORD i = 0; i < count; ++i)
			{
				CandidateAttributeEntry entry;
				memcpy(&entry, listBytes + kHeaderSize + i * kEntrySize, sizeof(entry));
				if (entry.attribute == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY &&
					entry.size >= sizeof(DWORD64) &&
					entry.value != NULL)
				{
					if (pSize)
						*pSize = entry.size;
					return reinterpret_cast<DWORD64*>(entry.value);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return NULL;
		}

		return NULL;
	}

	// Helper to extract mitigation policy DWORD64 pointer from LPSTARTUPINFOW (if STARTUPINFOEX)
	inline DWORD64* FindMitigationPolicyInStartupInfo(LPSTARTUPINFOW lpStartupInfo, SIZE_T* pSize = NULL)
	{
		if (pSize)
			*pSize = 0;
		if (!lpStartupInfo || lpStartupInfo->cb < sizeof(PL_STARTUPINFOEXW))
			return NULL;

		LPPL_STARTUPINFOEXW startupEx = reinterpret_cast<LPPL_STARTUPINFOEXW>(lpStartupInfo);
		if (!startupEx->lpAttributeList)
			return NULL;

		return FindMitigationPolicyEntry(startupEx->lpAttributeList, pSize);
	}

	// RAII guard for deferring CIG policy in caller's memory during CreateProcessInternalW
	class CScopedMitigationDeferral
	{
	public:
		explicit CScopedMitigationDeferral(DWORD64* policyPtr, SIZE_T policySize = sizeof(DWORD64))
			: m_policyPtr(policyPtr), m_policySize(policySize), m_deferred(FALSE),
			  m_originalPolicy(0), m_deferredSignatureFlags(0)
		{
			if (m_policyPtr && m_policySize >= sizeof(DWORD64))
			{
				__try
				{
					m_originalPolicy = *m_policyPtr;
					const DWORD64 cigBits = (m_originalPolicy & PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK);
					if (cigBits != 0)
					{
						PL_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy;
						sigPolicy.Flags = 0;
						if (cigBits == PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
						{
							sigPolicy.MicrosoftSignedOnly = 1;
						}
						else if (cigBits == PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE)
						{
							sigPolicy.MicrosoftSignedOnly = 1;
							sigPolicy.StoreSignedOnly = 1;
						}
						else
						{
							sigPolicy.MicrosoftSignedOnly = 1;
						}

						// Temporarily clear CIG bits so the child is created without CIG
						*m_policyPtr = m_originalPolicy & ~PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK;
						m_deferredSignatureFlags = sigPolicy.Flags;
						m_deferred = TRUE;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					m_deferred = FALSE;
					m_deferredSignatureFlags = 0;
				}
			}
		}

		~CScopedMitigationDeferral()
		{
			Restore();
		}

		BOOL IsDeferred() const
		{
			return m_deferred;
		}

		DWORD GetDeferredSignatureFlags() const
		{
			return m_deferredSignatureFlags;
		}

		void Restore()
		{
			if (m_deferred && m_policyPtr)
			{
				__try
				{
					*m_policyPtr = m_originalPolicy;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}
				m_deferred = FALSE;
			}
		}

	private:
		DWORD64* m_policyPtr;
		SIZE_T m_policySize;
		BOOL m_deferred;
		DWORD64 m_originalPolicy;
		DWORD m_deferredSignatureFlags;
	};

	// Restore CIG (Block Non-Microsoft Binaries) mitigation policy deferred at child creation.
	// 1. Check environment marker and extract saved flags.
	// 2. Consume and clear immediately to prevent inheritance to grandchild processes.
	// 3. Dynamically resolve SetProcessMitigationPolicy (safe fallback on XP/Vista/Win7).
	// 4. Invoke SetProcessMitigationPolicy to enforce original binary signature policy.
	inline BOOL RestoreCigPolicy()
	{
		DWORD flags = 0;
		if (!GetDeferredCigFlagsFromEnvironment(&flags))
			return FALSE;

		// First line of defense: erase immediately on consumption
		ClearDeferredCigEnvironment();

		HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
		if (!kernel32)
			return FALSE;

		PFN_SetProcessMitigationPolicy pfnSetProcessMitigationPolicy =
			reinterpret_cast<PFN_SetProcessMitigationPolicy>(
				GetProcAddress(kernel32, "SetProcessMitigationPolicy"));
		if (!pfnSetProcessMitigationPolicy)
		{
			// Legacy OS (WinXP / Win7) without mitigation support, graceful fallback
			return FALSE;
		}

		PL_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy;
		ZeroMemory(&policy, sizeof(policy));
		policy.Flags = flags;

		return pfnSetProcessMitigationPolicy(
			ProcessSignaturePolicy,
			&policy,
			sizeof(policy));
	}
}
