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
- whether an unsigned DLL loaded before runtime CIG remains loaded and callable,
  while a different unsigned DLL is blocked after CIG is enabled and a newly
  loaded Microsoft system DLL remains allowed.

## Build

From PowerShell:

```powershell
.\build.ps1
```

An x64 release executable is produced under `bin\x64`. The same directory also
contains `TestUnsignedA.dll` and `TestUnsignedB.dll`; keep all three files
together when copying the probe.

## Run and compare Windows 10/11

Run the x64 probe on each OS and save the complete output:

```powershell
.\bin\x64\MitigationAttributeProbe.exe | Tee-Object win10-x64.txt
```

Use `--dump` to include the complete, bounded attribute-list byte dump:

```powershell
.\bin\x64\MitigationAttributeProbe.exe --dump > win11-x64-dump.txt
```

`probe_execution=PASS` means the experiment completed and the candidate entry
layout and runtime CIG tests passed. The runtime test starts a fresh child with
no creation CIG, loads DLL A, enables `MicrosoftSignedOnly`, verifies DLL A is
still loaded and callable, confirms DLL B is blocked, and then loads a new
Microsoft system DLL. Read `total_length_layout_verdict` and
`candidate_entry_layout_verdict` separately: the two proposed structures are
not treated as one all-or-nothing layout.

A build-specific positive result does **not** turn the undocumented layout into
a supported ABI. Production code should still prefer public APIs or a shadow
list built by observing `UpdateProcThreadAttribute` calls.
