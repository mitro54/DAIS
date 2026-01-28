FROM ubuntu:24.04

# Use non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install OpenSSH Server and Python 3
RUN apt-get update && apt-get install -y \
    openssh-server \
    python3 \
    python3-pip \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
# Enable password auth
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Permit root login (optional, but easier for testing)
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create a test user 'dais' with password 'password'
RUN useradd -m -s /bin/bash dais && \
    echo 'dais:password' | chpasswd && \
    usermod -aG sudo dais

# Set root password for good measure
RUN echo 'root:password' | chpasswd

# Expose SSH port
EXPOSE 22

# Run SSH daemon
CMD ["/usr/sbin/sshd", "-D"]
