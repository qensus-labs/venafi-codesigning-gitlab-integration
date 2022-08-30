FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

ADD DOCKER-IMAGE-LICENSE.txt /license.txt

RUN apt-get update && apt-get install -y python3.10 python3-distutils python3-pip python3-apt openjdk-17-jdk alien

# RUN dnf install -y python38 java-11-openjdk-devel && \
#     dnf clean all

ADD VenafiCodeSigningClients.rpm /build/
RUN alien -i --scripts /build/VenafiCodeSigningClients.rpm && \
    rm -f /build/*.rpm

# RUN dnf install -y /build/*.rpm && \
#     rm -f /build/*.rpm

ADD . /build
RUN cd /build && \
    python3 setup.py install && \
    cd / && \
    rm -rf /build

ENV VENAFI_CONTAINER=true
ENV ISOLATE_SESSIONS=false
ENV GNUPGHOME=/tmp/.gnupg

# Sanity check
RUN venafi-version
