FROM rust:latest
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly

COPY Cargo.toml /code-security/Cargo.toml
COPY Cargo.lock /code-security/Cargo.lock
COPY src /code-security/src

WORKDIR /code-security

RUN cargo build --release \
    && mv /code-security/target/release/code-security /usr/local/bin/binary \
    && rm -rf /code-security

# Update the package list and upgrade the system
RUN apt-get update && \
    apt-get -y upgrade
    
## configure tzdata to avoid interactive prompt
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/London


RUN apt-get install -y --no-install-recommends tzdata \
    software-properties-common \
    python3-pip \
    default-jdk \
    npm \
    maven \
    composer \
    curl \
    wget \
    python3-venv && \
    pip3 install semgrep

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
ENV SBT_VERSION 1.7.2
RUN \
  curl -L -o sbt-$SBT_VERSION.deb https://repo.scala-sbt.org/scalasbt/debian/sbt-$SBT_VERSION.deb && \
  dpkg -i sbt-$SBT_VERSION.deb && \
  rm sbt-$SBT_VERSION.deb && \
  apt-get update && \
  apt-get -y install --no-install-recommends sbt

# Install npm
RUN npm install -g @cyclonedx/cdxgen pnpm
RUN export FETCH_LICENSE=true

# Install gradle
RUN wget https://services.gradle.org/distributions/gradle-7.0-bin.zip && \
    unzip gradle-7.0-bin.zip && \
    mv gradle-7.0 /opt/gradle && \
    export GRADLE_HOME=/opt/gradle && \
    export PATH=$PATH:$GRADLE_HOME/bin

RUN rm /code-security/gradle-7.0-bin.zip


ENTRYPOINT ["binary"]