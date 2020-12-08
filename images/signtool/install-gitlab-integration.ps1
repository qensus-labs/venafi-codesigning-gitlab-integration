$ErrorActionPreference = 'Stop'
Set-PSDebug -Trace 1
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

cd \build

$proc = Start-Process -Wait -NoNewWindow -PassThru python -ArgumentList 'setup.py bdist_wheel'
if ($proc.ExitCode -ne 0) {
    exit 1
}

$proc = Start-Process -Wait -NoNewWindow -PassThru pip -ArgumentList ('install',(Resolve-Path 'dist/*.whl'))
if ($proc.ExitCode -ne 0) {
    exit 1
}
