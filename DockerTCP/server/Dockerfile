FROM ubuntu

COPY myheader.h .
COPY sniff_server.c .

RUN apt-get update && \
    apt-get install -y \
        net-tools \
        gcc \
        libpcap-dev && \
    gcc -o sniff_server sniff_server.c -lpcap


