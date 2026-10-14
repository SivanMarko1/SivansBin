<#
.SYNOPSIS
  Offline, no-admin Prowler install that avoids Windows' 260-character path limit.

.DESCRIPTION
  For every wheel in the wheels folder, the script measures the longest file path inside it
  and picks a place where every file fits:
    1. normal pip install into the venv's site-packages, if it fits there;
    2. otherwise unpacked into a very short folder (default C:\pw), which is put on the
       venv's import path - this is what Prowler itself needs;
    3. otherwise, for pure-Python packages, imported straight from the .whl file
       (zip import) - this is what msgraph-sdk needs.
  It then creates launchers (prowler.cmd) for any command-line tools from steps 2 and 3,
  and checks that Prowler starts.

  Re-running the script deletes and rebuilds the venv and the short folder.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install-prowler.ps1 -WheelsDir C:\Users\SMarko\wheels -AddToPath
#>
param(
    [string]$WheelsDir = "$env:USERPROFILE\wheels",
    [string]$Root      = "C:\",          # venv goes to <Root>pv, unpacked packages to <Root>pw
    [string]$Python    = "python",       # same Python version the wheels were downloaded for
    [switch]$AddToPath                   # add the venv's Scripts folder to your user PATH
)

$ErrorActionPreference = "Stop"
$MaxPath = 259                           # Windows MAX_PATH (260) minus the terminating NUL

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "`nERROR: $msg" -ForegroundColor Red; exit 1 }
function Check-Exit($what) { if ($LASTEXITCODE -ne 0) { Fail "$what failed (exit code $LASTEXITCODE)." } }

function Remove-Dir($path) {
    if (Test-Path -LiteralPath $path) {
        # The \\?\ prefix lets rd delete paths longer than 260 characters left by failed installs.
        & cmd.exe /d /c "rd /s /q `"\\?\$path`" >nul 2>&1"
        if (Test-Path -LiteralPath $path) { Fail "Could not delete $path. Close any terminal or editor using it and try again." }
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-WheelInfo($file) {
    $zip = [IO.Compression.ZipFile]::OpenRead($file)
    try {
        $names = @($zip.Entries | Where-Object { $_.FullName -notmatch '/$' } | ForEach-Object { $_.FullName })
        $max   = ($names | Measure-Object -Property Length -Maximum).Maximum
        $ep    = $zip.Entries | Where-Object { $_.FullName -match '^[^/]+\.dist-info/entry_points\.txt$' } | Select-Object -First 1
        $entryPoints = $null
        if ($ep) {
            $reader = New-Object IO.StreamReader($ep.Open())
            try { $entryPoints = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        [pscustomobject]@{ MaxLen = [int]$max; EntryPoints = $entryPoints }
    } finally { $zip.Dispose() }
}

function Get-ConsoleScripts($text) {
    # Returns @{ name = "module:function" } from an entry_points.txt [console_scripts] section.
    $result = [ordered]@{}
    if (-not $text) { return $result }
    $inSection = $false
    foreach ($line in ($text -split "`r?`n")) {
        $l = $line.Trim()
        if ($l -match '^\[(.+)\]$') { $inSection = ($Matches[1] -eq 'console_scripts'); continue }
        if ($inSection -and $l -match '^([^=\s]+)\s*=\s*([\w\.]+):([\w\.]+)') {
            $result[$Matches[1]] = "$($Matches[2]):$($Matches[3])"
        }
    }
    return $result
}

# ---------------------------------------------------------------------------
Step "Checking inputs"

$WheelsDir = (Resolve-Path -LiteralPath $WheelsDir -ErrorAction SilentlyContinue).Path
if (-not $WheelsDir) { Fail "Wheels folder not found. Pass it with -WheelsDir." }
if (-not $Root.EndsWith("\")) { $Root += "\" }
$VenvDir = "${Root}pv"
$PkgDir  = "${Root}pw"
$ZipDir  = "$PkgDir\_zips"

try { $pyVersion = & $Python -c "import sys; print('%d.%d' % sys.version_info[:2])" } catch { $pyVersion = $null }
if ($LASTEXITCODE -ne 0 -or -not $pyVersion) { Fail "'$Python' does not run. Pass the full path to python.exe with -Python." }
Write-Host "Python $pyVersion, wheels in $WheelsDir"

$wheels = @(Get-ChildItem -LiteralPath $WheelsDir -File | Where-Object Name -like '*.whl')
$sdists = @(Get-ChildItem -LiteralPath $WheelsDir -File | Where-Object { $_.Name -match '\.(tar\.gz|zip)$' })
if (-not ($wheels | Where-Object Name -like 'prowler-*')) { Fail "No prowler-*.whl in $WheelsDir." }
Write-Host "$($wheels.Count) wheels, $($sdists.Count) source packages"

try {
    New-Item -ItemType Directory -Force -Path "${Root}_pw_write_test" | Out-Null
    Remove-Item -LiteralPath "${Root}_pw_write_test" -Force
} catch {
    Fail "You can't create folders in $Root. Map a short drive letter and use that instead:`n  subst P: `"$env:USERPROFILE`"`n  ...then re-run with -Root P:\  (run the subst line again after every reboot)."
}

# ---------------------------------------------------------------------------
Step "Creating a fresh venv at $VenvDir"

Remove-Dir $VenvDir
Remove-Dir $PkgDir
& $Python -m venv $VenvDir
Check-Exit "Creating the venv"
$py = "$VenvDir\Scripts\python.exe"
$sitePackages = (& $py -c "import sysconfig; print(sysconfig.get_paths()['purelib'])").Trim()
Check-Exit "Locating site-packages"

# ---------------------------------------------------------------------------
Step "Deciding where each package goes"

$pipFiles = New-Object System.Collections.Generic.List[string]
$unpack   = New-Object System.Collections.Generic.List[object]
$zipped   = New-Object System.Collections.Generic.List[object]

foreach ($w in $wheels) {
    $info = Get-WheelInfo $w.FullName
    $inSite = $sitePackages.Length + 1 + $info.MaxLen
    $inPkg  = $PkgDir.Length + 1 + $info.MaxLen
    if ($inSite -le $MaxPath) {
        $pipFiles.Add($w.FullName)
    } elseif ($inPkg -le $MaxPath) {
        $unpack.Add([pscustomobject]@{ File = $w; Info = $info })
        Write-Host "  unpack to $PkgDir : $($w.Name)  (longest path $inPkg)"
    } elseif ($w.Name -match '-none-any\.whl$') {
        $zipped.Add([pscustomobject]@{ File = $w; Info = $info })
        Write-Host "  import from zip  : $($w.Name)  (would need $inPkg characters)"
    } else {
        Fail "$($w.Name) has a $($info.MaxLen)-character path and contains compiled code, so it can't be installed without long path support. Ask IT to enable LongPathsEnabled."
    }
}
foreach ($s in $sdists) { $pipFiles.Add($s.FullName) }
Write-Host "  pip install      : $($pipFiles.Count) packages"

# ---------------------------------------------------------------------------
Step "Placing long-path packages"

$pthLines = New-Object System.Collections.Generic.List[string]
if ($unpack.Count -gt 0) {
    New-Item -ItemType Directory -Force -Path $PkgDir | Out-Null
    foreach ($u in $unpack) {
        & $py -I -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" $u.File.FullName $PkgDir
        Check-Exit "Unpacking $($u.File.Name)"
    }
    $pthLines.Add($PkgDir)
}
if ($zipped.Count -gt 0) {
    New-Item -ItemType Directory -Force -Path $ZipDir | Out-Null
    foreach ($z in $zipped) {
        $dest = Join-Path $ZipDir $z.File.Name
        Copy-Item -LiteralPath $z.File.FullName -Destination $dest
        $pthLines.Add($dest)
    }
}
if ($pthLines.Count -gt 0) {
    Set-Content -LiteralPath (Join-Path $sitePackages "_longpath_pkgs.pth") -Value $pthLines -Encoding ASCII
}

# ---------------------------------------------------------------------------
Step "Installing the remaining packages with pip"

if ($pipFiles.Count -gt 0) {
    # --no-deps: pip would otherwise try to (re)install the packages placed above.
    # --no-compile: .pyc files live in __pycache__ with longer names and could hit the limit.
    & $py -m pip install --no-index --no-deps --no-compile --disable-pip-version-check --find-links $WheelsDir $pipFiles.ToArray()
    Check-Exit "pip install"
}

# ---------------------------------------------------------------------------
Step "Creating launchers"

foreach ($pkg in @($unpack) + @($zipped)) {
    $scripts = Get-ConsoleScripts $pkg.Info.EntryPoints
    foreach ($name in $scripts.Keys) {
        $module, $func = $scripts[$name] -split ':', 2
        $code = "import sys;sys.path[:]=[p for p in sys.path if p];sys.argv[0]='$name';from $module import $($func.Split('.')[0]) as _f;sys.exit(_f$($func.Substring($func.Split('.')[0].Length))())"
        $cmd  = "@`"$py`" -c `"$code`" %*"
        Set-Content -LiteralPath "$VenvDir\Scripts\$name.cmd" -Value $cmd -Encoding ASCII
        Write-Host "  $VenvDir\Scripts\$name.cmd"
    }
}

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if ($parts -notcontains "$VenvDir\Scripts") {
        [Environment]::SetEnvironmentVariable("Path", (($parts + "$VenvDir\Scripts") -join ';'), "User")
        Write-Host "  Added $VenvDir\Scripts to your user PATH (open a new terminal to use it)."
    }
}

# ---------------------------------------------------------------------------
Step "Checking the install"

$loc = & $py -c "import prowler; print(prowler.__file__)"
Check-Exit "Importing prowler"
Write-Host "  prowler loads from $loc"

$launcher = "$VenvDir\Scripts\prowler.cmd"
if (-not (Test-Path -LiteralPath $launcher)) { $launcher = "$VenvDir\Scripts\prowler.exe" }
& $launcher -v
Check-Exit "Running prowler -v"

Write-Host "`nDone. Run Prowler with:  $launcher" -ForegroundColor Green
if (-not $AddToPath) { Write-Host "(Re-run with -AddToPath to be able to type just 'prowler'.)" }
