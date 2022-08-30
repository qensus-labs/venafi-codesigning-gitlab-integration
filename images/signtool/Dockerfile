# escape=`

FROM mcr.microsoft.com/windows/servercore:ltsc2019

ADD DOCKER-IMAGE-LICENSE.txt \license.txt

# Install pwsh
ADD images\signtool\install-pwsh.ps1 \build\
RUN powershell \build\install-pwsh.ps1

# Install Signtool
ADD images\signtool\install-signtool.ps1 \build\
RUN powershell \build\install-signtool.ps1

# Install Python
ADD requirements-dist-build.txt \build\
ADD images\signtool\install-python.ps1 \build\
RUN powershell \build\install-python.ps1

# Install Venafi client tools
ADD VenafiCodeSigningClients.msi \build\
ADD images\signtool\install-venafi-client-tools.ps1 \build\
RUN powershell \build\install-venafi-client-tools.ps1

# With VENAFICSPSilent, when an error occurs at the Venafi CSP driver level,
# that error is printed as part of the console output, instead of shown
# in a dialog box that requires the user to click OK.
ENV VENAFICSPSilent=1
ENV VENAFI_CONTAINER=true
ENV VENAFI_CONTAINER_REGISTER_CSP_DLL=true
ENV ISOLATE_SESSIONS=false
ENTRYPOINT ["venafi-container-init"]

# Install Gitlab integration
ADD . \build
ADD images\signtool\install-gitlab-integration.ps1 \build\
RUN powershell \build\install-gitlab-integration.ps1 && `
    rmdir /s /q \build

# Sanity check
RUN venafi-version
