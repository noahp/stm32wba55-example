# This is the newest Ubuntu version with simple support for STM32CubeIDE- it
# the Cube .deb has a dependency on the python2.7 package, which is no longer
# available in the latest Ubuntu LTS 24.04
FROM ubuntu:22.04

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

ARG STM32CUBE_VERSION=1.16.0_21983_20240628_1741
# Copy the installer file into the image. It needs to be downloaded into the
# directory where the Dockerfile is.
COPY en.st-stm32cubeide_${STM32CUBE_VERSION}_amd64.deb_bundle.sh.zip /tmp/stm32cubeide.sh.zip
RUN mkdir -p /tmp/stm32cubeide && \
    mv /tmp/stm32cubeide.sh.zip /tmp/stm32cubeide/stm32cubeide.sh.zip && \
    cd /tmp/stm32cubeide && \
    unzip stm32cubeide.sh.zip && \
    chmod +x st-stm32cubeide_${STM32CUBE_VERSION}_amd64.deb_bundle.sh && \
    # run the self-unpacker script, but don't actually install anything
    ./st-stm32cubeide_${STM32CUBE_VERSION}_amd64.deb_bundle.sh --target ./ --noexec && \
    # this is required to avoid an error during apt-get install
    chmod a+r /tmp/stm32cubeide/*.deb && \
    chmod 777 /tmp/stm32cubeide/*.deb && \
    # need to set this env var for unattended install. install everything
    # manually, to avoid issues with the installer script, which does not have
    # an unattended install mode.
    LICENSE_ALREADY_ACCEPTED=1 apt-get install -y \
    /tmp/stm32cubeide/st-st*.deb && \
    rm -rf /tmp/stm32cubeide
