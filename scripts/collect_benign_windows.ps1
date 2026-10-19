<#
Collect a benign PE set from this Windows machine for the raw-file track (report Section 3.5).

    powershell -ExecutionPolicy Bypass -File scripts\collect_benign_windows.ps1 -Count 600

Copies .exe/.dll files (10 KB - 30 MB) from Windows system folders and installed programs into
C:\fyp-data\benign_pe\<sha256>.bin, removes duplicates by hash, and writes manifest.csv with the
source path, product, version and publisher of each file, which the dissertation needs.
Programs from Program Files are taken first so the set is not only Microsoft system DLLs
(a source of shortcut learning, see docs/evaluation_protocol.md). Files are only copied,
never run. Afterwards benign_pe.zip is created for transfer into the VM.
#>
param(
    [int]$Count = 600,
    [string]$Out = "C:\fyp-data\benign_pe",
    [int]$Seed = 42
)

$ErrorActionPreference = "SilentlyContinue"
$roots = @(
    @{ Path = "C:\Program Files"; Share = 0.5 },
    @{ Path = "C:\Program Files (x86)"; Share = 0.2 },
    @{ Path = "C:\Windows\System32"; Share = 0.3 }
)
New-Item -ItemType Directory -Force $Out | Out-Null
$rng = New-Object System.Random $Seed
$seen = @{}
$rows = New-Object System.Collections.Generic.List[object]

foreach ($root in $roots) {
    $want = [int]($Count * $root.Share)
    $files = Get-ChildItem $root.Path -Recurse -File -Include *.exe, *.dll |
        Where-Object { $_.Length -ge 10KB -and $_.Length -le 30MB }
    $files = $files | Sort-Object { $rng.Next() }
    $taken = 0
    foreach ($f in $files) {
        if ($taken -ge $want) { break }
        $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
        if (-not $hash -or $seen.ContainsKey($hash)) { continue }
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { continue }  # MZ
        Copy-Item $f.FullName (Join-Path $Out "$hash.bin")
        $seen[$hash] = $true
        $vi = $f.VersionInfo
        $rows.Add([pscustomobject]@{
            sha256 = $hash; source_path = $f.FullName; product = $vi.ProductName
            version = $vi.FileVersion; publisher = $vi.CompanyName; size = $f.Length
        })
        $taken++
    }
    Write-Host ("{0,-28} {1} files" -f $root.Path, $taken)
}
$rows | Export-Csv (Join-Path $Out "manifest.csv") -NoTypeInformation -Encoding UTF8
$zip = "$Out.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "$Out\*" -DestinationPath $zip
Write-Host "collected $($rows.Count) benign PE files -> $Out (and $zip for the VM)"
