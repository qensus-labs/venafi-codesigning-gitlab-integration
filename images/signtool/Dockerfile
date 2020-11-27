# escape=`

FROM mcr.microsoft.com/windows/servercore:ltsc2019

# Install Signtool
ADD images\signtool\install-signtool.ps1 \build\
RUN powershell \build\install-signtool.ps1

# Install Python
ADD requirements-dist-build.txt \build\
ADD images\signtool\install-python.ps1 \build\
RUN powershell \build\install-python.ps1

# Install Venafi client tools
ADD VenafiCodeSigningClients-x64.msi \build\
ADD images\signtool\install-venafi-client-tools.ps1 \build\
RUN powershell \build\install-venafi-client-tools.ps1

# Install Gitlab integration
ADD . \build
ADD images\signtool\install-gitlab-integration.ps1 \build\
RUN powershell \build\install-gitlab-integration.ps1 && `
    rmdir /s /q \build
