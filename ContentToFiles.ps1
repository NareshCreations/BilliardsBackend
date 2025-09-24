# PowerShell Script to Recreate Files from Unique Delimiter Format
# Save this as: recreate-files-from-text-v2.ps1

param(
    [string]$InputFile = "billiards-src-files.txt",
    [string]$OutputDirectory = "recreated-src",
    [switch]$Force = $false,
    [switch]$Verbose = $false
)

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default { "White" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Write-FileContent {
    param(
        [string]$FilePath,
        [string]$Content
    )
    
    try {
        # Get absolute path and ensure directory exists
        $absolutePath = [System.IO.Path]::GetFullPath($FilePath)
        $directory = [System.IO.Path]::GetDirectoryName($absolutePath)
        
        # Create directory if it doesn't exist
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            if ($Verbose) { Write-Log "Created directory: $directory" -Level "Success" }
        }
        
        # Write content using Out-File for better compatibility
        $Content | Out-File -FilePath $absolutePath -Encoding UTF8 -Force
        Write-Log "Created file: $FilePath" -Level "Success"
        return $true
    }
    catch {
        Write-Log "Failed to create file: $FilePath - $($_.Exception.Message)" -Level "Error"
        if ($Verbose) {
            Write-Log "  Attempted path: $absolutePath" -Level "Error"
            Write-Log "  Directory: $directory" -Level "Error"
        }
        return $false
    }
}

function Parse-FileContent {
    param([string]$InputFile)
    
    if (-not (Test-Path $InputFile)) {
        Write-Log "Input file not found: $InputFile" -Level "Error"
        return @()
    }
    
    Write-Log "Reading input file: $InputFile"
    
    try {
        $content = Get-Content $InputFile -Raw -Encoding UTF8
    }
    catch {
        Write-Log "Failed to read input file: $($_.Exception.Message)" -Level "Error"
        return @()
    }
    
    if (-not $content) {
        Write-Log "Input file is empty or could not be read" -Level "Error"
        return @()
    }
    
    Write-Log "Parsing file structure with unique delimiter..."
    
    $files = @()
    $lines = $content -split "`r?`n"
    $currentFile = $null
    $currentContent = @()
    $inFileContent = $false
    $separatorPattern = "^=+$"
    
    # Unique delimiter pattern: <<Naresh><Claud->Script->File>>: 1. src\app.ts
    $fileHeaderPattern = '^<<Naresh><Claud->Script->File>>:\s*\d+\.\s+(.+)$'
    
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        
        # Check for unique file header pattern
        if ($line -match $fileHeaderPattern) {
            # Save previous file if exists
            if ($currentFile -and $currentContent.Count -gt 0) {
                $cleanContent = ($currentContent -join "`n").Trim()
                if ($cleanContent.Length -gt 0) {
                    $files += @{
                        Path = $currentFile
                        Content = $cleanContent
                    }
                }
            }
            
            # Start new file
            $currentFile = $matches[1].Trim()
            $currentContent = @()
            $inFileContent = $false
            
            if ($Verbose) { Write-Log "Found file: $currentFile" }
        }
        # Check for separator line (====)
        elseif ($line -match $separatorPattern) {
            $inFileContent = $true
        }
        # Collect file content
        elseif ($inFileContent -and $currentFile) {
            $currentContent += $line
        }
    }
    
    # Don't forget the last file
    if ($currentFile -and $currentContent.Count -gt 0) {
        $cleanContent = ($currentContent -join "`n").Trim()
        if ($cleanContent.Length -gt 0) {
            $files += @{
                Path = $currentFile
                Content = $cleanContent
            }
        }
    }
    
    Write-Log "Found $($files.Count) files to recreate"
    return $files
}

function Normalize-FilePath {
    param([string]$Path, [string]$BaseDirectory)
    
    # Convert backslashes to forward slashes and remove any leading path separators
    $normalized = $Path -replace '\\', '/'
    $normalized = $normalized.TrimStart('/')
    
    # Convert back to Windows path separators and join with base directory
    $relativePath = $normalized -replace '/', [System.IO.Path]::DirectorySeparatorChar
    return Join-Path $BaseDirectory $relativePath
}

# Main script execution
try {
    Write-Log "Starting file recreation process..."
    Write-Log "Input file: $InputFile"
    Write-Log "Output directory: $OutputDirectory"
    Write-Log "Looking for delimiter: <<Naresh><Claud->Script->File>>"
    
    # Check if input file exists
    if (-not (Test-Path $InputFile)) {
        Write-Log "Input file not found: $InputFile" -Level "Error"
        Write-Log "Please ensure the file exists and try again." -Level "Error"
        exit 1
    }
    
    # Get current directory for path resolution
    $currentDir = Get-Location
    if ($Verbose) { Write-Log "Current directory: $currentDir" }
    
    # Create full path for output directory
    if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
        $OutputDirectory = Join-Path $currentDir $OutputDirectory
    }
    Write-Log "Full output path: $OutputDirectory"
    
    # Check if output directory exists and handle accordingly
    if (Test-Path $OutputDirectory) {
        if ($Force) {
            Write-Log "Output directory exists. Force flag is set - will overwrite files." -Level "Warning"
        }
        else {
            Write-Log "Output directory already exists: $OutputDirectory" -Level "Warning"
            $choice = Read-Host "Do you want to continue and potentially overwrite files? (y/N)"
            if ($choice -notmatch '^[Yy]') {
                Write-Log "Operation cancelled by user."
                exit 0
            }
        }
    }
    else {
        # Create output directory
        try {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
            Write-Log "Created output directory: $OutputDirectory" -Level "Success"
        }
        catch {
            Write-Log "Failed to create output directory: $OutputDirectory - $($_.Exception.Message)" -Level "Error"
            exit 1
        }
    }
    
    # Parse the input file
    $parsedFiles = Parse-FileContent $InputFile
    
    if ($parsedFiles.Count -eq 0) {
        Write-Log "No files found in input file or parsing failed." -Level "Error"
        Write-Log "Make sure the input file uses the format: <<Naresh><Claud->Script->File>>: X. filename" -Level "Error"
        exit 1
    }
    
    # Statistics
    $successCount = 0
    $errorCount = 0
    $totalFiles = $parsedFiles.Count
    
    Write-Log "Creating $totalFiles files..."
    
    # Create each file
    foreach ($fileInfo in $parsedFiles) {
        $fullPath = Normalize-FilePath $fileInfo.Path $OutputDirectory
        
        if ($Verbose) {
            Write-Log "Processing: $($fileInfo.Path)"
            Write-Log "  Full path: $fullPath"
            Write-Log "  Content length: $($fileInfo.Content.Length) characters"
        }
        
        if (Write-FileContent -FilePath $fullPath -Content $fileInfo.Content) {
            $successCount++
        }
        else {
            $errorCount++
        }
        
        # Progress indicator
        $progress = [math]::Round(($successCount + $errorCount) / $totalFiles * 100, 1)
        Write-Progress -Activity "Creating Files" -Status "Progress: $progress%" -PercentComplete $progress
    }
    
    Write-Progress -Completed -Activity "Creating Files"
    
    # Final summary
    Write-Log ""
    Write-Log "============== SUMMARY ==============" -Level "Success"
    Write-Log "Total files processed: $totalFiles" -Level "Success"
    Write-Log "Successfully created: $successCount" -Level "Success"
    Write-Log "Errors encountered: $errorCount" -Level $(if ($errorCount -gt 0) { "Warning" } else { "Success" })
    Write-Log "Output directory: $OutputDirectory" -Level "Success"
    Write-Log "====================================" -Level "Success"
    
    if ($errorCount -eq 0) {
        Write-Log "All files recreated successfully!" -Level "Success"
        Write-Log ""
        Write-Log "You can now navigate to the output directory and use the recreated files."
        exit 0
    }
    else {
        Write-Log "Some files failed to create. Check the log above for details." -Level "Warning"
        exit 1
    }
}
catch {
    Write-Log "Unexpected error occurred: $($_.Exception.Message)" -Level "Error"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "Error"
    exit 1
}

<#
USAGE EXAMPLES:

1. Basic usage (creates files in 'recreated-src' directory):
   .\recreate-files-from-text-v2.ps1

2. Specify custom input file and output directory:
   .\recreate-files-from-text-v2.ps1 -InputFile "my-files.txt" -OutputDirectory "my-project"

3. Force overwrite existing files without prompting:
   .\recreate-files-from-text-v2.ps1 -Force

4. Verbose output to see detailed progress:
   .\recreate-files-from-text-v2.ps1 -Verbose

5. Full example with all parameters:
   .\recreate-files-from-text-v2.ps1 -InputFile "billiards-src-files.txt" -OutputDirectory "restored-project" -Force -Verbose

KEY IMPROVEMENTS IN VERSION 2:
- Uses unique delimiter: <<Naresh><Claud->Script->File>>: X. filename
- Eliminates false positives from content containing "File:"
- More robust parsing with unique pattern matching
- Better error messages indicating expected format
- Compatible with updated display script format
#>