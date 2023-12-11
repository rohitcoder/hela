FROM rust:latest
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly

COPY Cargo.toml /hela/Cargo.toml
COPY Cargo.lock /hela/Cargo.lock
COPY src /hela/src

WORKDIR /hela

RUN cargo build +nightly --release \
    && mv /hela/target/release/Hela /usr/local/bin/hela \
    && rm -rf /hela

# Update the package list and upgrade the system
RUN apt-get update && \
    apt-get -y upgrade
    
## configure tzdata to avoid interactive prompt
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/London


RUN apt-get install -y --no-install-recommends tzdata software-properties-common python3-pip default-jdk npm maven curl wget python3-venv
RUN pip3 install semgrep --break-system-packages

## Lets upgrade nodejs
RUN npm install n -g
RUN n stable

## Install go using wget and then set the path
RUN wget https://go.dev/dl/go1.20.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.20.3.linux-amd64.tar.gz && \
    rm go1.20.3.linux-amd64.tar.gz

ENV GOPATH=$HOME/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Install trufflehog

RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.37.0/trufflehog_3.37.0_linux_arm64.tar.gz && \
    tar -xvf trufflehog_3.37.0_linux_arm64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    rm trufflehog_3.37.0_linux_arm64.tar.gz

RUN go install github.com/google/osv-scanner/cmd/osv-scanner@v1

# Install npm
RUN npm install -g @cyclonedx/cdxgen pnpm
RUN export FETCH_LICENSE=true


ENTRYPOINT ["hela"]
