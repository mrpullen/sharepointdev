#Requires -Version 3.0
#Requires -Module Az.Compute

Import-Module Az.Compute -ErrorAction SilentlyContinue

function Build-DSCArchive() {
    $dscSourceFolder = Join-Path -Path $PSScriptRoot -ChildPath "..\dsc" -Resolve
    Write-Host $dscSourceFolder
    if (Test-Path $dscSourceFolder) {
        $dscSourceFilePaths = @(Get-ChildItem $dscSourceFolder -File -Filter "*.ps1" | ForEach-Object -Process {$_.FullName})
        foreach ($dscSourceFilePath in $dscSourceFilePaths) {
            $dscArchiveFilePath = $dscSourceFilePath.Substring(0, $dscSourceFilePath.Length - 4) + ".zip"
            Write-Host "Publsihing $($dscSourceFilePath) to $($dscArchiveFilePath)"
            Publish-AzVMDscConfiguration $dscSourceFilePath -OutputArchivePath $dscArchiveFilePath -Force -Verbose
        }
    }
}

Build-DSCArchive