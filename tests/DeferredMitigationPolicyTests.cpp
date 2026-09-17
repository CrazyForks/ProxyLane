#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <vector>
#include "DeferredMitigationPolicy.h"

static void TestEnvironmentVariableDetectionAndClear()
{
	using namespace DeferredMitigationPolicy;

	// 1. Initially unset
	SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, NULL);
	DWORD flags = 0;
	assert(!GetDeferredCigFlagsFromEnvironment(&flags));
	assert(flags == 0);
	assert(!ShouldRestoreCigFromEnvironment());

	// 2. Set to non-positive value (e.g. "0")
	SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, L"0");
	assert(!GetDeferredCigFlagsFromEnvironment(&flags));
	assert(!ShouldRestoreCigFromEnvironment());

	// 3. Set to "1"
	SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, L"1");
	assert(GetDeferredCigFlagsFromEnvironment(&flags));
	assert(flags == 1);
	assert(ShouldRestoreCigFromEnvironment());

	// 4. Set to "3" (MicrosoftSignedOnly | StoreSignedOnly)
	SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, L"3");
	assert(GetDeferredCigFlagsFromEnvironment(&flags));
	assert(flags == 3);
	assert(ShouldRestoreCigFromEnvironment());

	// 5. ClearDeferredCigEnvironment
	ClearDeferredCigEnvironment();
	assert(!ShouldRestoreCigFromEnvironment());

	WCHAR checkBuffer[8] = { 0 };
	DWORD length = GetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, checkBuffer, 8);
	assert(length == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND);
}

static void TestRestoreCigPolicyLifecycle()
{
	using namespace DeferredMitigationPolicy;

	// When unset, RestoreCigPolicy should return FALSE and do nothing
	SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, NULL);
	assert(!RestoreCigPolicy());

	// When set to "3", calling RestoreCigPolicy should:
	// - Erase the environment variable (self-destruct)
	// - Attempt to call SetProcessMitigationPolicy if supported on this OS
	SetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, L"3");
	assert(ShouldRestoreCigFromEnvironment());

	RestoreCigPolicy();

	WCHAR checkBuffer[8] = { 0 };
	DWORD length = GetEnvironmentVariableW(PROXYLANE_DEFERRED_CIG_ENV_W, checkBuffer, 8);
	assert(!ShouldRestoreCigFromEnvironment());
	assert(length == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND);
}

static void TestFindMitigationPolicyAndDeferral()
{
	using namespace DeferredMitigationPolicy;

	// Test NULL and invalid inputs
	assert(FindMitigationPolicyEntry(NULL) == NULL);
	assert(FindMitigationPolicyInStartupInfo(NULL) == NULL);

	STARTUPINFOW plainSi = { 0 };
	plainSi.cb = sizeof(plainSi);
	assert(FindMitigationPolicyInStartupInfo(&plainSi) == NULL);

	// Test with actual attribute list
	SIZE_T bytes = 0;
	InitializeProcThreadAttributeList(NULL, 2, 0, &bytes);
	if (bytes == 0)
	{
		// Legacy platform without attribute list support
		return;
	}

	std::vector<BYTE> buffer(bytes, 0);
	PPROC_THREAD_ATTRIBUTE_LIST attrList = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(&buffer[0]);
	BOOL initOk = InitializeProcThreadAttributeList(attrList, 2, 0, &bytes);
	assert(initOk);

	// Initially empty list - no mitigation policy present
	assert(FindMitigationPolicyEntry(attrList) == NULL);

	// Add parent process attribute (index 0)
	HANDLE hParent = GetCurrentProcess();
	UpdateProcThreadAttribute(attrList, 0, 0x00020000 /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS */, &hParent, sizeof(hParent), NULL, NULL);
	assert(FindMitigationPolicyEntry(attrList) == NULL);

	// Add mitigation policy with CIG ALWAYS_ON and some non-CIG bits (e.g. DEP / ASLR)
	const DWORD64 kNonCigBits = 0x0000000000000003ULL; // DEP always on
	DWORD64 originalMitigation = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON | kNonCigBits;
	BOOL updateOk = UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &originalMitigation, sizeof(originalMitigation), NULL, NULL);
	assert(updateOk);

	// Find the entry
	SIZE_T foundSize = 0;
	DWORD64* pFound = FindMitigationPolicyEntry(attrList, &foundSize);
	assert(pFound == &originalMitigation);
	assert(foundSize == sizeof(originalMitigation));
	assert((*pFound & PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK) == PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

	// Test FindMitigationPolicyInStartupInfo
	PL_STARTUPINFOEXW siEx = { 0 };
	siEx.StartupInfo.cb = sizeof(siEx);
	siEx.lpAttributeList = attrList;
	SIZE_T siExSize = 0;
	assert(FindMitigationPolicyInStartupInfo(&siEx.StartupInfo, &siExSize) == &originalMitigation);
	assert(siExSize == sizeof(originalMitigation));

	// Test CScopedMitigationDeferral with ALWAYS_ON:
	// Only CIG bits are cleared, non-CIG bits are preserved!
	{
		CScopedMitigationDeferral deferral(pFound, foundSize);
		assert(deferral.IsDeferred() == TRUE);
		assert(deferral.GetDeferredSignatureFlags() == 1);
		// Inside scope: CIG bits must be cleared!
		assert((*pFound & PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK) == 0);
		// Non-CIG bits MUST remain intact!
		assert((*pFound & kNonCigBits) == kNonCigBits);
	}
	// After scope: original policy MUST be restored!
	assert(*pFound == originalMitigation);

	// Test CScopedMitigationDeferral with ALLOW_STORE:
	DWORD64 allowStoreMitigation = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE | kNonCigBits;
	{
		CScopedMitigationDeferral deferral(&allowStoreMitigation, sizeof(allowStoreMitigation));
		assert(deferral.IsDeferred() == TRUE);
		assert(deferral.GetDeferredSignatureFlags() == 3); // MicrosoftSignedOnly | StoreSignedOnly
		assert((allowStoreMitigation & PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK) == 0);
		assert((allowStoreMitigation & kNonCigBits) == kNonCigBits);
	}
	assert(allowStoreMitigation == (PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE | kNonCigBits));

	// Test CScopedMitigationDeferral when policy has no CIG (e.g. only non-CIG bits)
	DWORD64 onlyOtherPolicy = kNonCigBits;
	{
		CScopedMitigationDeferral deferral(&onlyOtherPolicy, sizeof(onlyOtherPolicy));
		assert(deferral.IsDeferred() == FALSE);
		assert(deferral.GetDeferredSignatureFlags() == 0);
		assert(onlyOtherPolicy == kNonCigBits);
	}

	DeleteProcThreadAttributeList(attrList);
}

int main()
{
	TestEnvironmentVariableDetectionAndClear();
	TestRestoreCigPolicyLifecycle();
	TestFindMitigationPolicyAndDeferral();
	puts("DeferredMitigationPolicy tests passed");
	return 0;
}
