FROM rockylinux:8

ADD DOCKER-IMAGE-LICENSE.txt /license.txt

RUN dnf install -y python39 java-11-openjdk-devel && \
    dnf clean all

ADD venafi-codesigningclients-linux-x86_64.rpm /build/
RUN dnf install -y /build/*.rpm && \
    rm -f /build/*.rpm

ADD . /build
RUN cd /build && \
    python3 setup.py install && \
    cd / && \
    rm -rf /build

ENV VENAFI_CONTAINER=true
ENV ISOLATE_SESSIONS=false

# Sanity check
RUN venafi-version
