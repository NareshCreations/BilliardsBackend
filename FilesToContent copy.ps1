# PowerShell Script to Display All Files in src Directory with Content
# Save this as: display-src-files.ps1

param(
    [string]$SrcPath = "src",
    [string]$OutputFile = $null,
    [string[]]$ExcludeExtensions = @(".log", ".tmp", ".cache"),
    [string[]]$IncludeExtensions = @(".ts", ".js", ".json", ".md"),
    [int]$MaxFileSize = 100KB
)

function Display-FileContent {
    param(
        [string]$FilePath,
        [int]$Index,
        [System.IO.StreamWriter]$Writer = $null
    )
    
    $relativePath = $FilePath.Replace((Get-Location).Path, "").TrimStart('\', '/')
    $separator = "=" * 80
    
    $header = @"
$Index. File: $relativePath
$separator

"@
    
    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        $output = $header + $content + "`n`n"
        
        if ($Writer) {
            $Writer.Write($output)
        } else {
            Write-Output $output
        }
    }
    catch {
        $errorOutput = $header + "ERROR: Could not read file - $($_.Exception.Message)`n`n"
        if ($Writer) {
            $Writer.Write($errorOutput)
        } else {
            Write-Output $errorOutput
        }
    }
}

function Should-IncludeFile {
    param([string]$FilePath)
    
    $fileInfo = Get-Item $FilePath
    $extension = $fileInfo.Extension.ToLower()
    
    # Check file size
    if ($fileInfo.Length -gt $MaxFileSize) {
        Write-Warning "Skipping large file: $FilePath (Size: $($fileInfo.Length) bytes)"
        return $false
    }
    
    # Check if extension should be excluded
    if ($ExcludeExtensions -contains $extension) {
        return $false
    }
    
    # If include extensions specified, check if file extension is in the list
    if ($IncludeExtensions.Count -gt 0) {
        return $IncludeExtensions -contains $extension
    }
    
    # Skip common binary/cache files
    $excludePatterns = @("node_modules", ".git", "dist", "build", ".cache", "logs")
    foreach ($pattern in $excludePatterns) {
        if ($FilePath -like "*$pattern*") {
            return $false
        }
    }
    
    return $true
}

# Main script execution
try {
    if (-not (Test-Path $SrcPath)) {
        Write-Error "Source path '$SrcPath' does not exist!"
        exit 1
    }
    
    Write-Host "Reading files from: $SrcPath" -ForegroundColor Green
    Write-Host "Include extensions: $($IncludeExtensions -join ', ')" -ForegroundColor Yellow
    Write-Host "Max file size: $($MaxFileSize / 1KB)KB" -ForegroundColor Yellow
    Write-Host ""
    
    # Get all files recursively
    $allFiles = Get-ChildItem -Path $SrcPath -File -Recurse | 
                Where-Object { Should-IncludeFile $_.FullName } |
                Sort-Object FullName
    
    if ($allFiles.Count -eq 0) {
        Write-Warning "No files found matching criteria in $SrcPath"
        exit 0
    }
    
    Write-Host "Found $($allFiles.Count) files to process" -ForegroundColor Green
    Write-Host ""
    
    $writer = $null
    
    if ($OutputFile) {
        $outputDir = Split-Path $OutputFile -Parent
        if ($outputDir -and (-not (Test-Path $outputDir))) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $writer = New-Object System.IO.StreamWriter($OutputFile, $false, [System.Text.Encoding]::UTF8)
        Write-Host "Writing output to: $OutputFile" -ForegroundColor Green
    }
    
    $index = 1
    foreach ($file in $allFiles) {
        Display-FileContent -FilePath $file.FullName -Index $index -Writer $writer
        $index++
        
        # Show progress for console output
        if (-not $writer) {
            Write-Progress -Activity "Processing Files" -Status "File $index of $($allFiles.Count)" -PercentComplete (($index / $allFiles.Count) * 100)
        }
    }
    
    if (-not $writer) {
        Write-Progress -Completed -Activity "Processing Files"
    }
    
    Write-Host "Successfully processed $($allFiles.Count) files!" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($writer) {
        $writer.Close()
        $writer.Dispose()
    }
}

# Usage examples at the end of the script as comments:
<#
USAGE EXAMPLES:

1. Basic usage (display all TypeScript files in src):
   .\display-src-files.ps1

2. Specify custom source path:
   .\display-src-files.ps1 -SrcPath "C:\MyProject\src"

3. Save output to file:
   .\display-src-files.ps1 -OutputFile "all-files.txt"

4. Include only specific file types:
   .\display-src-files.ps1 -IncludeExtensions @(".ts", ".js", ".json")

5. Exclude specific file types:
   .\display-src-files.ps1 -ExcludeExtensions @(".test.ts", ".spec.ts")

6. Full example with all options:
   .\display-src-files.ps1 -SrcPath "src" -OutputFile "output.txt" -IncludeExtensions @(".ts", ".js") -MaxFileSize 50KB

7. For your billiards project:
   .\display-src-files.ps1 -SrcPath "src" -OutputFile "billiards-src-files.txt" -IncludeExtensions @(".ts")
#>