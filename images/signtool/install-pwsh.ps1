$ErrorActionPreference = 'Stop'
Set-PSDebug -Trace 1

Invoke-WebRequest -UseBasicParsing -OutFile \build\pwsh-installer.msi `
    https://github.com/PowerShell/PowerShell/releases/download/v7.2.6/PowerShell-7.2.6-win-x64.msi

$proc = Start-Process -Wait -NoNewWindow -PassThru msiexec `
    -ArgumentList ('/package','\build\pwsh-installer.msi', `
    '/quiet','REGISTER_MANIFEST=1','ADD_PATH=1','/l*vx','\build\pwsh-install.log')
if ($proc.ExitCode -ne 0) {
    Get-Content \build\pwsh-install.log
    exit 1
}

