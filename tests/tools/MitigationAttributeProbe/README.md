# MitigationAttributeProbe

This diagnostic tool tests a proposed internal layout for
`PROC_THREAD_ATTRIBUTE_LIST` without trusting any undocumented length field.
It confines all reads to the exact allocation size returned by
`InitializeProcThreadAttributeList`.

The probe reports:

- whether the first `DWORD` equals the allocation size (`TotalLength` hypothesis);
- whether the candidate `{ Attribute, Size, Value }` entry occurs exactly once;
- whether the same entry shape remains observable in a three-attribute list;
- whether changing the known mitigation value through the discovered value
  pointer changes the effective CIG policy observed on a suspended child.

## Build

From PowerShell:

```powershell
.\build.ps1
```

Both Win32 and x64 release executables are produced under `bin`.

## Run and compare Windows 10/11

Run both architectures on each OS and save the complete output:

```powershell
.\bin\x64\MitigationAttributeProbe.exe | Tee-Object win10-x64.txt
.\bin\Win32\MitigationAttributeProbe.exe | Tee-Object win10-x86.txt
```

Use `--dump` to include the complete, bounded attribute-list byte dump:

```powershell
.\bin\x64\MitigationAttributeProbe.exe --dump > win11-x64-dump.txt
```

`probe_execution=PASS` means the experiment completed and the candidate entry
layout passed its kernel behavior check. Read `total_length_layout_verdict` and
`candidate_entry_layout_verdict` separately: the two proposed structures are
not treated as one all-or-nothing layout.

A build-specific positive result does **not** turn the undocumented layout into
a supported ABI. Production code should still prefer public APIs or a shadow
list built by observing `UpdateProcThreadAttribute` calls.
