$ErrorActionPreference = 'Stop'; `
Set-PSDebug -Trace 1

Invoke-WebRequest -UseBasicParsing -Out \winsdksetup.exe `
    https://download.microsoft.com/download/1/c/3/1c3d5161-d9e9-4e4b-9b43-b70fe8be268c/windowssdk/winsdksetup.exe

$proc = Start-Process -Wait -NoNewWindow -PassThru \winsdksetup.exe `
    -ArgumentList ('/Features','OptionId.SigningTools','/Quiet','/NoRestart','/Log','\winsdksetup.log')
if ($proc.ExitCode -ne 0) {
    Get-Content \winsdksetup.log
    exit 1
}

New-Item -ItemType SymbolicLink -Path \winsdk `
    -Target "${env:ProgramFiles(x86)}\Windows` Kits\10\bin\10.0.19041.0"
setx /M PATH "${env:PATH};C:\winsdk\x64"

Remove-Item -Force \winsdksetup*
