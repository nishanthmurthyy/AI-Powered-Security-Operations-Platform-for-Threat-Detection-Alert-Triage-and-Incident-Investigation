# ==========================================================
# Agentic AI Folder Structure Creator
# Safe Version - Does NOT overwrite existing files
# ==========================================================

# Change this to your project root
$ProjectRoot = "C:\Users\Administrator\OneDrive\Documents\3rd sem\project Lab\AI-Powered-Security-Operations-Platform-for-Threat-Detection-Alert-Triage-and-Incident-Investigation"

Set-Location $ProjectRoot

Write-Host ""
Write-Host "Creating Agentic AI folder structure..." -ForegroundColor Cyan

# ----------------------------------------------------------
# List of folders
# ----------------------------------------------------------

$folders = @(
    "agentic_ai",
    "agentic_ai\agents",
    "agentic_ai\prompts",
    "agentic_ai\tools"
)

foreach ($folder in $folders) {

    if (!(Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder | Out-Null
        Write-Host "Created Folder: $folder" -ForegroundColor Green
    }
    else {
        Write-Host "Folder Exists: $folder" -ForegroundColor Yellow
    }

}

# ----------------------------------------------------------
# List of files
# ----------------------------------------------------------

$files = @(
    "agentic_ai\llm.py",
    "agentic_ai\orchestrator.py",

    "agentic_ai\agents\url_agent.py",
    "agentic_ai\agents\auth_agent.py",
    "agentic_ai\agents\mitre_agent.py",
    "agentic_ai\agents\report_agent.py",

    "agentic_ai\prompts\url_prompt.txt",
    "agentic_ai\prompts\auth_prompt.txt",

    "agentic_ai\tools\whois_tool.py",
    "agentic_ai\tools\ssl_tool.py",
    "agentic_ai\tools\dns_tool.py"
)

foreach ($file in $files) {

    if (!(Test-Path $file)) {
        New-Item -ItemType File -Path $file | Out-Null
        Write-Host "Created File: $file" -ForegroundColor Green
    }
    else {
        Write-Host "File Exists: $file" -ForegroundColor Yellow
    }

}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Agentic AI structure is ready." -ForegroundColor Green
Write-Host "No existing folders or files were modified." -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan