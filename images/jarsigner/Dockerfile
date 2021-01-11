FROM centos:8

RUN dnf install -y python38 java-11-openjdk-devel && \
    dnf clean all

ADD venafi-codesigningclients-20.2.0-linux-x86_64.rpm /build/
RUN dnf install -y /build/*.rpm && \
    rm -f /build/*.rpm

ADD . /build
RUN cd /build && \
    python3 setup.py install && \
    cd / && \
    rm -rf /build

ENV VENAFI_CONTAINER=true
ENV ISOLATE_SESSIONS=false
