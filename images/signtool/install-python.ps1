$ErrorActionPreference = 'Stop'
Set-PSDebug -Trace 1

Invoke-WebRequest -UseBasicParsing -OutFile \build\python-installer.exe `
    https://www.python.org/ftp/python/3.8.6/python-3.8.6-amd64.exe

$proc = Start-Process -Wait -NoNewWindow -PassThru \build\python-installer.exe `
    -ArgumentList ('/quiet','/log','\build\python-installer.log','TargetDir=C:\Python','InstallAllUsers=1','PrependPath=1','Include_doc=0','Include_tcltk=0')
if ($proc.ExitCode -ne 0) {
    Get-Output \build\python-installer.log
    exit 1
}

$proc = Start-Process -Wait -NoNewWindow -PassThru C:\Python\Scripts\pip `
    -ArgumentList ('install','-U','-r','\build\requirements-dist-build.txt')
if ($proc.ExitCode -ne 0) {
    exit 1
}

Remove-Item -Force \build\python-installer.*
