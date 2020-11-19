FROM mcr.microsoft.com/windows/nanoserver:sac2016

ADD . \\build

RUN powershell -Command \
    $ErrorActionPreference = 'Stop'; \
    Invoke-WebRequest https://www.python.org/ftp/python/3.8.6/python-3.8.6-amd64.exe -OutFile \\build\\python.zip; \
    Start-Process \\build\\python.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item -Force \\build\\python.exe
RUN powershell -Command \
    $ErrorActionPreference = 'Stop'; \
    cd \\build; \
    Start-Process python3 setup.py bdist_wheel; \
    Start-Process pip3 install dist/*.whl; \
    cd \\; \
    Remove-Item -Recurse -Force \\build

# TODO add user account?
# TODO download venafi client tools
