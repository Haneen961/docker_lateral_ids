FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        nginx \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/sshd && \
    echo 'root:supersecret-no-match' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "<h1>victim web</h1>" > /var/www/html/index.html

EXPOSE 22 80

CMD bash -c "service nginx start && /usr/sbin/sshd -D"

