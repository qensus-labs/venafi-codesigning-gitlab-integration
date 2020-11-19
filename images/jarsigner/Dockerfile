FROM centos:8

ADD . /build

RUN dnf install -y python38 java-11-openjdk-devel && \
    dnf clean all
RUN cd /build && \
    python3 setup.py bdist_wheel && \
    pip3 install dist/*.whl && \
    cd / && \
    rm -rf /build

# TODO add user account
# TODO download venafi client tools
