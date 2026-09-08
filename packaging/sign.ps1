<#
.SYNOPSIS
    Authenticode-sign the built binaries, with timestamping and verification.

.DESCRIPTION
    Works with all three ways a code signing key can live these days:

      * a USB token or a certificate in your Windows store  -> -Thumbprint / -Subject
      * a cloud signing service with a signtool plugin      -> -Dlib / -Metadata
                                                                (Azure Trusted Signing,
                                                                 SSL.com eSigner, ...)
      * whatever signtool can pick on its own               -> -AutoSelect

    Timestamping is not optional. Without it every signature you ship stops
    validating the day the certificate expires; with it, signatures stay valid
    for the life of the timestamp authority's own certificate.

.EXAMPLE
    .\packaging\sign.ps1 -Thumbprint ABC123... -Path build-nuitka\gui_launcher.dist\subaru-pak-gui.exe

.EXAMPLE
    .\packaging\sign.ps1 -Dlib "C:\ats\Azure.CodeSigning.Dlib.dll" -Metadata "C:\ats\metadata.json" -Path dist\*.exe
#>
[CmdletBinding(DefaultParameterSetName = 'Store')]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Path,

    [Parameter(ParameterSetName = 'Store')]
    [string] $Thumbprint,

    [Parameter(ParameterSetName = 'Store')]
    [string] $Subject,

    [Parameter(ParameterSetName = 'Store')]
    [switch] $AutoSelect,

    [Parameter(ParameterSetName = 'Cloud', Mandatory = $true)]
    [string] $Dlib,

    [Parameter(ParameterSetName = 'Cloud', Mandatory = $true)]
    [string] $Metadata,

    [string] $SignTool,

    # Tried in order; a busy timestamp authority is a common transient failure.
    [string[]] $TimestampUrls = @(
        'http://timestamp.digicert.com',
        'http://timestamp.sectigo.com',
        'http://time.certum.pl',
        'http://ts.ssl.com'
    )
)

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    if ($SignTool) {
        if (-not (Test-Path $SignTool)) { throw "signtool not found at $SignTool" }
        return $SignTool
    }
    $found = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }

    $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin",
               "${env:ProgramFiles}\Windows Kits\10\bin")
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $candidate = Get-ChildItem $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object { $_.VersionInfo.ProductVersion } -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw @'
signtool.exe was not found. Install the "Windows SDK Signing Tools for Desktop Apps"
component of the Windows SDK, or pass -SignTool with an explicit path.
'@
}

$tool = Find-SignTool
Write-Host "signtool: $tool"

$targets = @()
foreach ($item in $Path) {
    $resolved = Resolve-Path $item -ErrorAction SilentlyContinue
    if (-not $resolved) { throw "no file matched '$item'" }
    $targets += $resolved | ForEach-Object { $_.Path }
}
Write-Host "signing $($targets.Count) file(s)"

# Identity arguments differ per signing backend; everything else is shared.
if ($PSCmdlet.ParameterSetName -eq 'Cloud') {
    $identity = @('/dlib', $Dlib, '/dmdf', $Metadata)
} elseif ($Thumbprint) {
    $identity = @('/sha1', ($Thumbprint -replace '[^0-9A-Fa-f]', ''))
} elseif ($Subject) {
    $identity = @('/n', $Subject)
} elseif ($AutoSelect) {
    $identity = @('/a')
} else {
    throw "give one of -Thumbprint, -Subject, -AutoSelect, or the -Dlib/-Metadata pair"
}

foreach ($target in $targets) {
    $signed = $false
    foreach ($url in $TimestampUrls) {
        Write-Host "  $([IO.Path]::GetFileName($target))  (timestamp: $url)"
        $arguments = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $url) +
                     $identity + @('/v', $target)
        & $tool @arguments
        if ($LASTEXITCODE -eq 0) { $signed = $true; break }
        Write-Warning "  that timestamp authority failed; trying the next one"
    }
    if (-not $signed) { throw "signing failed for $target" }
}

Write-Host "`nverifying..."
foreach ($target in $targets) {
    & $tool verify /pa /v $target
    if ($LASTEXITCODE -ne 0) { throw "verification failed for $target" }
}
Write-Host "`nAll files signed and verified." -ForegroundColor Green
