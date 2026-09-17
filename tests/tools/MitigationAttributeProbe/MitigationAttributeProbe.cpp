#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK \
    (0x00000003ULL << 44)
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON \
    (0x00000001ULL << 44)
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF \
    (0x00000002ULL << 44)
#endif

namespace {

// This is deliberately a hypothesis, not a production declaration. The tool
// searches for a byte sequence matching this shape only inside a buffer whose
// exact allocation size was returned by InitializeProcThreadAttributeList.
struct CandidateAttributeEntry {
    DWORD_PTR attribute;
    SIZE_T size;
    PVOID value;
};

struct AttributeList {
    std::vector<BYTE> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;

    ~AttributeList() {
        if (list) {
            DeleteProcThreadAttributeList(list);
        }
    }

    bool Initialize(DWORD count) {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, count, 0, &bytes);
        if (!bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }
        storage.assign(bytes, 0xCC);
        list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(list, count, 0, &bytes)) {
            list = nullptr;
            return false;
        }
        return true;
    }
};

struct Match {
    SIZE_T offset;
    CandidateAttributeEntry entry;
};

std::wstring ErrorText(DWORD error) {
    wchar_t* text = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&text),
        0,
        nullptr);
    std::wstring result = length && text ? std::wstring(text, length) : L"unknown error";
    if (text) {
        LocalFree(text);
    }
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) {
        result.pop_back();
    }
    return result;
}

std::wstring Hex64(ULONGLONG value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << std::setw(16)
           << std::setfill(L'0') << value;
    return stream.str();
}

std::wstring QuoteCommandLineArgument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    size_t slashCount = 0;
    for (std::wstring::const_iterator it = value.begin(); it != value.end(); ++it) {
        if (*it == L'\\') {
            ++slashCount;
            continue;
        }
        if (*it == L'\"') {
            quoted.append(slashCount * 2 + 1, L'\\');
            quoted.push_back(L'\"');
            slashCount = 0;
            continue;
        }
        quoted.append(slashCount, L'\\');
        slashCount = 0;
        quoted.push_back(*it);
    }
    quoted.append(slashCount * 2, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

std::wstring DirectoryOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

void PrintOsVersion() {
    typedef LONG(WINAPI* RtlGetVersionFn)(OSVERSIONINFOW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionFn rtlGetVersion = ntdll
        ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"))
        : nullptr;
    OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtlGetVersion && rtlGetVersion(&version) == 0) {
        std::wcout << L"os=" << version.dwMajorVersion << L'.'
                   << version.dwMinorVersion << L" build=" << version.dwBuildNumber
                   << L" architecture=" << (sizeof(void*) == 8 ? L"x64" : L"x86")
                   << L'\n';
    } else {
        std::wcout << L"os=unknown architecture="
                   << (sizeof(void*) == 8 ? L"x64" : L"x86") << L'\n';
    }
}

void DumpBytes(const std::vector<BYTE>& storage) {
    for (SIZE_T offset = 0; offset < storage.size(); offset += 16) {
        std::wcout << std::hex << std::uppercase << std::setw(4)
                   << std::setfill(L'0') << offset << L": ";
        for (SIZE_T column = 0; column < 16; ++column) {
            if (offset + column < storage.size()) {
                std::wcout << std::setw(2)
                           << static_cast<unsigned>(storage[offset + column]) << L' ';
            } else {
                std::wcout << L"   ";
            }
        }
        std::wcout << L'\n';
    }
    std::wcout << std::dec << std::setfill(L' ');
}

std::vector<Match> FindExactEntryMatches(
    const std::vector<BYTE>& storage,
    DWORD_PTR expectedAttribute,
    SIZE_T expectedSize,
    const void* expectedValue) {
    std::vector<Match> matches;
    for (SIZE_T offset = 0;
         offset + sizeof(CandidateAttributeEntry) <= storage.size();
         offset += alignof(void*)) {
        CandidateAttributeEntry candidate = {};
        memcpy(&candidate, storage.data() + offset, sizeof(candidate));
        if (candidate.attribute == expectedAttribute &&
            candidate.size == expectedSize &&
            candidate.value == expectedValue) {
            matches.push_back({offset, candidate});
        }
    }
    return matches;
}

bool AddAttribute(
    AttributeList& attributes,
    DWORD_PTR attribute,
    void* value,
    SIZE_T size) {
    if (UpdateProcThreadAttribute(
            attributes.list, 0, attribute, value, size, nullptr, nullptr)) {
        return true;
    }
    const DWORD error = GetLastError();
    std::wcerr << L"UpdateProcThreadAttribute(" << Hex64(attribute)
               << L") failed: " << error << L" (" << ErrorText(error) << L")\n";
    return false;
}

enum class ExpectedCig { Disabled, Enabled };

bool CreateSuspendedProbeAndCheckCig(
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList,
    ExpectedCig expected,
    bool* observedEnabled) {
    wchar_t systemDirectory[MAX_PATH] = {};
    if (!GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory))) {
        return false;
    }
    std::wstring application = std::wstring(systemDirectory) + L"\\cmd.exe";
    std::wstring commandLine = L"\"" + application + L"\" /d /c exit 0";
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOEXW startup = {};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributeList;
    PROCESS_INFORMATION process = {};
    const DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                        CREATE_NO_WINDOW;
    if (!CreateProcessW(
            application.c_str(),
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            flags,
            nullptr,
            nullptr,
            &startup.StartupInfo,
            &process)) {
        const DWORD error = GetLastError();
        std::wcerr << L"CreateProcessW failed: " << error << L" ("
                   << ErrorText(error) << L")\n";
        return false;
    }

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
    const BOOL queried = GetProcessMitigationPolicy(
        process.hProcess, ProcessSignaturePolicy, &policy, sizeof(policy));
    const DWORD queryError = queried ? ERROR_SUCCESS : GetLastError();
    *observedEnabled = queried &&
        (policy.MicrosoftSignedOnly || policy.StoreSignedOnly || policy.MitigationOptIn);

    TerminateProcess(process.hProcess, 0);
    WaitForSingleObject(process.hProcess, 5000);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    if (!queried) {
        std::wcerr << L"GetProcessMitigationPolicy failed: " << queryError << L" ("
                   << ErrorText(queryError) << L")\n";
        return false;
    }
    return *observedEnabled == (expected == ExpectedCig::Enabled);
}

bool RunSingleAttributeTest(bool dump) {
    std::wcout << L"\n[test: single mitigation attribute]\n";
    AttributeList attributes;
    if (!attributes.Initialize(1)) {
        std::wcerr << L"InitializeProcThreadAttributeList failed\n";
        return false;
    }

    DWORD64 mitigation =
        PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if (!AddAttribute(
            attributes,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &mitigation,
            sizeof(mitigation))) {
        return false;
    }

    const DWORD firstDword = *reinterpret_cast<const DWORD*>(attributes.storage.data());
    const bool totalLengthHypothesis = firstDword == attributes.storage.size();
    std::wcout << L"allocated_bytes=" << attributes.storage.size()
               << L" first_dword=" << firstDword
               << L" proposed_TotalLength="
               << (totalLengthHypothesis ? L"MATCH" : L"NO_MATCH") << L'\n';
    std::wcout << L"total_length_layout_verdict="
               << (totalLengthHypothesis ? L"OBSERVED_MATCH" : L"REJECTED_ON_THIS_BUILD")
               << L'\n';

    const std::vector<Match> matches = FindExactEntryMatches(
        attributes.storage,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        sizeof(mitigation),
        &mitigation);
    std::wcout << L"candidate_entry_matches=" << matches.size();
    if (!matches.empty()) {
        std::wcout << L" first_offset=" << matches.front().offset;
    }
    std::wcout << L'\n';

    if (dump) {
        DumpBytes(attributes.storage);
    }

    bool cigEnabled = false;
    const bool enabledTest = CreateSuspendedProbeAndCheckCig(
        attributes.list, ExpectedCig::Enabled, &cigEnabled);
    std::wcout << L"kernel_check_ALWAYS_ON=" << (enabledTest ? L"PASS" : L"FAIL")
               << L" observed_cig=" << (cigEnabled ? L"on" : L"off") << L'\n';

    bool mutationTest = false;
    if (matches.size() == 1 && matches.front().entry.value == &mitigation) {
        DWORD64* valueViaCandidate =
            static_cast<DWORD64*>(matches.front().entry.value);
        *valueViaCandidate =
            PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF;
        bool cigAfterMutation = true;
        mutationTest = CreateSuspendedProbeAndCheckCig(
            attributes.list, ExpectedCig::Disabled, &cigAfterMutation);
        std::wcout << L"candidate_pointer_mutation_ALWAYS_OFF="
                   << (mutationTest ? L"PASS" : L"FAIL")
                   << L" observed_cig=" << (cigAfterMutation ? L"on" : L"off")
                   << L'\n';
    } else {
        std::wcout << L"candidate_pointer_mutation_ALWAYS_OFF=SKIP"
                      L" reason=unique exact entry not found\n";
    }

    std::wcout << L"candidate_entry_layout_verdict="
               << (matches.size() == 1 && enabledTest && mutationTest
                       ? L"SUPPORTED_ON_THIS_BUILD"
                       : L"NOT_SUPPORTED_ON_THIS_BUILD")
               << L'\n';

    return matches.size() == 1 && enabledTest && mutationTest;
}

bool RunMultipleAttributeTest(bool dump) {
    std::wcout << L"\n[test: three public attributes]\n";
    AttributeList attributes;
    if (!attributes.Initialize(3)) {
        std::wcerr << L"InitializeProcThreadAttributeList failed\n";
        return false;
    }

    DWORD64 mitigation =
        PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    HANDLE parent = GetCurrentProcess();
    HANDLE inheritableEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!inheritableEvent) {
        return false;
    }
    HANDLE handleList[1] = {inheritableEvent};

    bool ok = AddAttribute(
                  attributes,
                  PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                  &mitigation,
                  sizeof(mitigation)) &&
              AddAttribute(
                  attributes,
                  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                  &parent,
                  sizeof(parent)) &&
              AddAttribute(
                  attributes,
                  PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                  handleList,
                  sizeof(handleList));
    if (!ok) {
        CloseHandle(inheritableEvent);
        return false;
    }

    const std::vector<Match> mitigationMatches = FindExactEntryMatches(
        attributes.storage,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        sizeof(mitigation),
        &mitigation);
    const std::vector<Match> parentMatches = FindExactEntryMatches(
        attributes.storage,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        sizeof(parent),
        &parent);
    const std::vector<Match> handleMatches = FindExactEntryMatches(
        attributes.storage,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        sizeof(handleList),
        handleList);

    std::wcout << L"allocated_bytes=" << attributes.storage.size() << L'\n'
               << L"mitigation_matches=" << mitigationMatches.size()
               << L" parent_matches=" << parentMatches.size()
               << L" handle_list_matches=" << handleMatches.size() << L'\n';
    if (!mitigationMatches.empty() && !parentMatches.empty() && !handleMatches.empty()) {
        std::wcout << L"offsets mitigation=" << mitigationMatches.front().offset
                   << L" parent=" << parentMatches.front().offset
                   << L" handles=" << handleMatches.front().offset << L'\n';
    }
    if (dump) {
        DumpBytes(attributes.storage);
    }

    CloseHandle(inheritableEvent);
    return mitigationMatches.size() == 1 && parentMatches.size() == 1 &&
           handleMatches.size() == 1;
}

typedef DWORD(WINAPI* ProbeValueFunction)();

int RunRuntimeCigChild(const wchar_t* dllAPath, const wchar_t* dllBPath) {
    std::wcout << L"\n[test: runtime CIG after a third-party DLL is loaded]\n";

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY initialPolicy = {};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy,
                                    &initialPolicy, sizeof(initialPolicy))) {
        const DWORD error = GetLastError();
        std::wcerr << L"initial_GetProcessMitigationPolicy=FAIL error=" << error
                   << L" (" << ErrorText(error) << L")\n";
        return 20;
    }
    const bool initiallyEnabled = initialPolicy.MicrosoftSignedOnly ||
        initialPolicy.StoreSignedOnly || initialPolicy.MitigationOptIn;
    std::wcout << L"initial_cig=" << (initiallyEnabled ? L"on" : L"off") << L'\n';
    if (initiallyEnabled) {
        std::wcerr << L"runtime_test_precondition=FAIL reason=child already has CIG\n";
        return 21;
    }

    HMODULE moduleA = LoadLibraryW(dllAPath);
    if (!moduleA) {
        const DWORD error = GetLastError();
        std::wcerr << L"load_unsigned_a=FAIL error=" << error << L" ("
                   << ErrorText(error) << L")\n";
        return 22;
    }
    std::wcout << L"load_unsigned_a=PASS\n";

    ProbeValueFunction probeA = reinterpret_cast<ProbeValueFunction>(
        GetProcAddress(moduleA, "ProbeValue"));
    if (!probeA || probeA() != 0xA11A0001UL) {
        std::wcerr << L"call_unsigned_a_before_cig=FAIL\n";
        return 23;
    }
    std::wcout << L"call_unsigned_a_before_cig=PASS\n";

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY requestedPolicy = {};
    requestedPolicy.MicrosoftSignedOnly = 1;
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &requestedPolicy,
                                    sizeof(requestedPolicy))) {
        const DWORD error = GetLastError();
        std::wcerr << L"SetProcessMitigationPolicy=FAIL error=" << error << L" ("
                   << ErrorText(error) << L")\n";
        return 24;
    }
    std::wcout << L"SetProcessMitigationPolicy=PASS\n";

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY effectivePolicy = {};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy,
                                    &effectivePolicy, sizeof(effectivePolicy))) {
        const DWORD error = GetLastError();
        std::wcerr << L"effective_GetProcessMitigationPolicy=FAIL error=" << error
                   << L" (" << ErrorText(error) << L")\n";
        return 25;
    }
    const bool effectiveCig = effectivePolicy.MicrosoftSignedOnly != 0;
    std::wcout << L"effective_cig=" << (effectiveCig ? L"on" : L"off") << L'\n';
    if (!effectiveCig) {
        return 26;
    }

    HMODULE observedA = GetModuleHandleW(L"TestUnsignedA.dll");
    std::wcout << L"unsigned_a_still_loaded=" <<
        (observedA == moduleA ? L"PASS" : L"FAIL") << L'\n';
    if (observedA != moduleA) {
        return 27;
    }
    if (probeA() != 0xA11A0001UL) {
        std::wcerr << L"call_unsigned_a_after_cig=FAIL\n";
        return 28;
    }
    std::wcout << L"call_unsigned_a_after_cig=PASS\n";

    // Loading an image rejected by CIG can raise the system's "Bad Image"
    // critical-error dialog.  Keep this negative test non-interactive and
    // restore the caller's thread error mode immediately afterwards.
    DWORD previousErrorMode = 0;
    if (!SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX,
                            &previousErrorMode)) {
        const DWORD error = GetLastError();
        std::wcerr << L"set_thread_error_mode=FAIL error=" << error << L'\n';
        return 29;
    }
    SetLastError(ERROR_SUCCESS);
    HMODULE moduleB = LoadLibraryW(dllBPath);
    const DWORD unsignedBError = moduleB ? ERROR_SUCCESS : GetLastError();
    const BOOL restoredErrorMode = SetThreadErrorMode(previousErrorMode, nullptr);
    std::wcout << L"bad_image_dialog_suppression="
               << (restoredErrorMode ? L"PASS" : L"RESTORE_FAIL") << L'\n';
    if (!restoredErrorMode) {
        return 30;
    }
    if (moduleB) {
        std::wcerr << L"load_unsigned_b=FAIL reason=unexpectedly loaded\n";
        FreeLibrary(moduleB);
        return 31;
    }
    // Do not call FormatMessage after CIG is active: formatting can lazily load
    // localized resource modules and would add an unrelated image-load test.
    std::wcout << L"load_unsigned_b=BLOCKED error=" << unsignedBError
               << L" expected_error="
               << ERROR_INVALID_IMAGE_HASH << L'\n';
    if (unsignedBError != ERROR_INVALID_IMAGE_HASH) {
        std::wcout << L"load_unsigned_b_error_verdict=NONSTANDARD_BUT_BLOCKED\n";
    } else {
        std::wcout << L"load_unsigned_b_error_verdict=EXPECTED\n";
    }

    const wchar_t* systemCandidates[] = {
        L"winhttp.dll", L"dbghelp.dll", L"cryptui.dll", L"propsys.dll"
    };
    const wchar_t* selectedSystemDll = nullptr;
    for (size_t i = 0; i < ARRAYSIZE(systemCandidates); ++i) {
        if (!GetModuleHandleW(systemCandidates[i])) {
            selectedSystemDll = systemCandidates[i];
            break;
        }
    }
    if (!selectedSystemDll) {
        std::wcerr << L"select_new_microsoft_dll=FAIL reason=all candidates already loaded\n";
        return 32;
    }

    wchar_t systemDirectory[MAX_PATH] = {};
    if (!GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory))) {
        return 33;
    }
    std::wstring systemDllPath = std::wstring(systemDirectory) + L"\\" +
        selectedSystemDll;
    HMODULE systemModule = LoadLibraryW(systemDllPath.c_str());
    if (!systemModule) {
        const DWORD error = GetLastError();
        std::wcerr << L"load_microsoft_dll=FAIL name=" << selectedSystemDll
                   << L" error=" << error << L'\n';
        return 34;
    }
    std::wcout << L"load_microsoft_dll=PASS name=" << selectedSystemDll << L'\n';
    FreeLibrary(systemModule);

    std::wcout << L"runtime_cig_child_result=PASS\n";
    return 0;
}

bool RunRuntimeCigParentTest() {
    std::wcout << L"\n[test: launch runtime CIG child without creation CIG]\n";
    wchar_t executablePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, executablePath, ARRAYSIZE(executablePath))) {
        return false;
    }
    const std::wstring directory = DirectoryOf(executablePath);
    const std::wstring dllAPath = directory + L"\\TestUnsignedA.dll";
    const std::wstring dllBPath = directory + L"\\TestUnsignedB.dll";
    if (GetFileAttributesW(dllAPath.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(dllBPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"runtime_cig_assets=FAIL reason=test DLLs are missing\n";
        return false;
    }

    std::wstring commandLine = QuoteCommandLineArgument(executablePath) +
        L" --runtime-cig-child " + QuoteCommandLineArgument(dllAPath) + L" " +
        QuoteCommandLineArgument(dllBPath);
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(executablePath, mutableCommand.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, directory.c_str(), &startup, &process)) {
        const DWORD error = GetLastError();
        std::wcerr << L"runtime_cig_CreateProcess=FAIL error=" << error << L" ("
                   << ErrorText(error) << L")\n";
        return false;
    }
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) {
        std::wcerr << L"runtime_cig_child_wait=FAIL result=" << wait << L'\n';
        TerminateProcess(process.hProcess, 0xEE);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        return false;
    }
    DWORD exitCode = 0;
    const BOOL gotExitCode = GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    std::wcout << L"runtime_cig_child_exit=" << exitCode << L'\n';
    const bool passed = gotExitCode && exitCode == 0;
    std::wcout << L"runtime_cig_parent_result=" << (passed ? L"PASS" : L"FAIL")
               << L'\n';
    return passed;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
	std::wcout << std::unitbuf;
	std::wcerr << std::unitbuf;

	if (argc == 4 && wcscmp(argv[1], L"--runtime-cig-child") == 0) {
		return RunRuntimeCigChild(argv[2], argv[3]);
	}

    bool dump = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--dump") == 0) {
            dump = true;
        } else if (wcscmp(argv[i], L"--help") == 0 ||
                   wcscmp(argv[i], L"-h") == 0) {
            std::wcout << L"Usage: MitigationAttributeProbe.exe [--dump]\n";
            return 0;
        } else {
            std::wcerr << L"Unknown argument: " << argv[i] << L'\n';
            return 2;
        }
    }

    std::wcout << L"MitigationAttributeProbe version=3\n";
    PrintOsVersion();
    std::wcout << L"candidate_entry_size=" << sizeof(CandidateAttributeEntry)
               << L" pointer_size=" << sizeof(void*) << L'\n';
    std::wcout << L"mitigation_attribute="
               << Hex64(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) << L'\n';
    std::wcout << L"cig_mask="
               << Hex64(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK)
               << L'\n';

    const bool single = RunSingleAttributeTest(dump);
    const bool multiple = RunMultipleAttributeTest(dump);
    const bool runtimeCig = RunRuntimeCigParentTest();
    const bool passed = single && multiple && runtimeCig;
    std::wcout << L"\nprobe_execution=" << (passed ? L"PASS" : L"FAIL") << L'\n';
    return passed ? 0 : 1;
}
