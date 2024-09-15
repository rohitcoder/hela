FROM rust:latest;ls;
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly-2024-02-04
COPY Cargo.toml /hela/Cargo.toml
COPY Cargo.lock /hela/Cargo.lock
COPY src /hela/src

WORKDIR /hela

RUN cargo build --release
RUN mv /hela/target/release/Hela /usr/local/bin/hela
RUN rm -rf /hela

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
RUN wget https://go.dev/dl/go1.21.9.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.9.linux-amd64.tar.gz && \
    rm go1.21.9.linux-amd64.tar.gz

ENV GOPATH=$HOME/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Install trufflehog
## curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN go install github.com/google/osv-scanner/cmd/osv-scanner@v1

# Install npm
RUN npm install -g @cyclonedx/cdxgen pnpm
RUN export FETCH_LICENSE=true


ENTRYPOINT ["hela"]
