# Docker image for load testing tools
# Includes: wrk, Apache Bench (ab), hey, curl

FROM alpine:latest

# Install dependencies
RUN apk add --no-cache \
    build-base \
    git \
    curl \
    apache2-utils \
    ca-certificates \
    libgcc \
    linux-headers \
    make \
    musl-dev \
    perl \
    openssl-dev \
    openssl-libs-static

# Install wrk (HTTP benchmarking tool)
WORKDIR /tmp
RUN git clone https://github.com/wg/wrk.git && \
    cd wrk && \
    make && \
    cp wrk /usr/local/bin/ && \
    chmod +x /usr/local/bin/wrk && \
    cd .. && \
    rm -rf wrk

# Install hey (Go-based load testing tool)
RUN apk add --no-cache go && \
    go install github.com/rakyll/hey@latest && \
    cp /root/go/bin/hey /usr/local/bin/ && \
    chmod +x /usr/local/bin/hey && \
    apk del go

# Create working directory
WORKDIR /loadtest

# Copy test scripts
COPY scripts/*.sh /loadtest/
RUN chmod +x /loadtest/*.sh

# Default command
CMD ["/bin/sh"]


