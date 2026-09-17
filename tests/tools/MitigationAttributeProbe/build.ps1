$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer\vswhere.exe was not found.'
}

$installation = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
if (-not $installation) {
    throw 'A Visual Studio installation containing MSBuild was not found.'
}

$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvarsall.bat'
$source = Join-Path $PSScriptRoot 'MitigationAttributeProbe.cpp'
$dllSource = Join-Path $PSScriptRoot 'UnsignedProbeDll.cpp'

$build = @{ Platform = 'x64'; Architecture = 'x64' }
& {
    $outputDirectory = Join-Path $PSScriptRoot "bin\$($build.Platform)"
    $objectDirectory = Join-Path $PSScriptRoot "obj\$($build.Platform)"
    New-Item -ItemType Directory -Force -Path $outputDirectory, $objectDirectory | Out-Null
    $output = Join-Path $outputDirectory 'MitigationAttributeProbe.exe'
    $object = Join-Path $objectDirectory 'MitigationAttributeProbe.obj'
    $command = 'call "{0}" {1} >nul && cl.exe /nologo /std:c++14 /EHsc /W4 /WX /O2 /MT /DUNICODE /D_UNICODE /Fo"{2}" /Fe:"{3}" "{4}"' -f `
        $vcvars, $build.Architecture, $object, $output, $source
    & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for $($build.Platform)."
    }

    foreach ($dll in @(
        @{ Name = 'TestUnsignedA'; Value = '0xA11A0001UL' },
        @{ Name = 'TestUnsignedB'; Value = '0xB22B0002UL' }
    )) {
        $dllOutput = Join-Path $outputDirectory "$($dll.Name).dll"
        $dllObject = Join-Path $objectDirectory "$($dll.Name).obj"
        $importLibrary = Join-Path $objectDirectory "$($dll.Name).lib"
        $dllCommand = 'call "{0}" {1} >nul && cl.exe /nologo /LD /W4 /WX /O2 /MT /DPROBE_VALUE={2} /Fo"{3}" /Fe:"{4}" "{5}" /link /IMPLIB:"{6}"' -f `
            $vcvars, $build.Architecture, $dll.Value, $dllObject, $dllOutput, $dllSource, $importLibrary
        & $env:ComSpec /d /s /c $dllCommand
        if ($LASTEXITCODE -ne 0) {
            throw "DLL build failed for $($build.Platform) $($dll.Name)."
        }
    }
}

Write-Host "Built:"
Write-Host "  $PSScriptRoot\bin\x64\MitigationAttributeProbe.exe"
Write-Host "The x64 directory also contains TestUnsignedA.dll and TestUnsignedB.dll."
