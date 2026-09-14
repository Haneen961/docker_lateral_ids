FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        hydra \
        curl \
        iputils-ping \
        netcat-openbsd \
        openssh-client \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Tiny wordlist for hydra ssh brute-force demo
RUN printf "%s" \
    "password" "123456" "root" "admin" "toor" "letmein" \
    "qwerty" "p@ssw0rd" "docker" "changeme" "test" "guest" \
    "redhat" "ubuntu" "user" "1234" > /opt/wordlist.txt

WORKDIR /work

