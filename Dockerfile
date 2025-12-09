FROM ubuntu:latest

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    docker.io \
    sudo \
    curl \
    vim \
    nano \
    iputils-ping \
    net-tools \
    wget \
    git \
    python3-pip \
    unzip \
    neofetch \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create SSH privilege separation directory
RUN mkdir -p /run/sshd

# Create docker group, user account, and add to sudo + docker groups
RUN groupadd -f docker && \
    useradd -m -s /bin/bash user && \
    echo "user:pwd" | chpasswd && \
    usermod -aG sudo,docker user

# Set root password
RUN echo "root:rootpwd" | chpasswd

# Allow root SSH login
RUN sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Expose SSH port
EXPOSE 22

# Start SSH + Docker automatically
CMD ["/start.sh"]