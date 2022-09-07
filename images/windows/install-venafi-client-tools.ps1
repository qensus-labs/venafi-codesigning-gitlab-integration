$ErrorActionPreference = 'Stop'
Set-PSDebug -Trace 1

$proc = Start-Process -Wait -NoNewWindow -PassThru msiexec `
    -ArgumentList ('/i','\build\VenafiCodeSigningClients.msi', `
    '/passive','/l*vx','\build\venafi-install.log')
if ($proc.ExitCode -ne 0) {
    Get-Content \build\venafi-install.log
    exit 1
}

setx /M PATH "${env:PATH};${env:ProgramFiles}\Venafi CodeSign Protect"
