FROM ubuntu:24.04

# Typical dockerfile stuff, try to suppress interactive prompts when installing
# packages
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for STM32CubeIDE
RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    ca-certificates \
    # we use git to clone our project when we build in GitHub actions
    git \
    # part of the Cube install script uses "killall", which is in psmisc
    psmisc \
    # we use this to extract the Cube installer
    unzip
    # don't clear apt cache, the stm32cubeide installer needs it
    # && rm -rf /var/lib/apt/lists/*

ARG STM32CUBE_VERSION=1.17.0_23558_20241125_2245
# Copy the installer file into the image. It needs to be downloaded into the
# directory where the Dockerfile is.
COPY en.st-stm32cubeide_${STM32CUBE_VERSION}_amd64.deb_bundle.sh.zip /tmp/stm32cubeide.sh.zip
RUN mkdir -p /tmp/stm32cubeide && \
    mv /tmp/stm32cubeide.sh.zip /tmp/stm32cubeide/stm32cubeide.sh.zip && \
    cd /tmp/stm32cubeide && \
    unzip stm32cubeide.sh.zip && \
    chmod +x st-stm32cubeide_${STM32CUBE_VERSION}_amd64.deb_bundle.sh && \
    LICENSE_ALREADY_ACCEPTED=1 ./st-stm32cubeide_${STM32CUBE_VERSION}_amd64.deb_bundle.sh && \
    rm -rf /tmp/stm32cubeide
