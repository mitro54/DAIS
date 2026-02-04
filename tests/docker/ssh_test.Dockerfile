FROM ubuntu:24.04

# Install SSH server and basic tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    curl \
    vim \
    nano \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create a test user
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:pw' | chpasswd && \
    usermod -aG sudo testuser

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
