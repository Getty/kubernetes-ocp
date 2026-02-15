# OCP - Omni Control Plane Docker Image
# Build: docker build -t ocp .
# Use:   docker run -v $(pwd):/project ocp status

FROM debian:trixie AS ocp-base
ARG VERSION="develop"

ENV DEBIAN_FRONTEND="noninteractive"

ARG OCP_UID=1000
ARG OCP_GID=1000

# Install Base Packages ======================================================

RUN apt-get update -y && apt-get install -y --no-install-recommends \
  curl ca-certificates git openssh-client \
  libexpat1-dev zlib1g-dev libssl-dev libssh2-1-dev build-essential \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install kubectl =============================================================

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
  && chmod +x kubectl \
  && mv kubectl /usr/local/bin/

# Install Perl ================================================================

ENV PERL_VERSION="5.42.0"
ENV PERL_SHA256="e093ef184d7f9a1b9797e2465296f55510adb6dab8842b0c3ed53329663096dc"

RUN mkdir -p /usr/src/perl && cd /usr/src/perl \
  && curl -sfSLO https://www.cpan.org/src/5.0/perl-${PERL_VERSION}.tar.gz \
  && echo -n "${PERL_SHA256}  perl-${PERL_VERSION}.tar.gz" | sha256sum -cw - \
  && echo "-j$(nproc)" >~/.proverc \
  && tar --strip-components=1 -xzf perl-${PERL_VERSION}.tar.gz -C /usr/src/perl \
  && rm perl-${PERL_VERSION}.tar.gz \
  && ./Configure -des \
  && make -j$(nproc) install

RUN PERL_MM_USE_DEFAULT=1 cpan -i App::cpanminus App::cpm \
  && cpanm --n Net::SSLeay && cpanm LWP::Protocol::https \
  && cd ~ && rm -rf ~/.cpan /usr/src/perl /tmp/*

# Install ocp user and environment ============================================

RUN mkdir /home/ocp && useradd -s /bin/bash -d /home/ocp -u $OCP_UID ocp && \
  chown ocp.ocp /home/ocp && rm -rf /tmp/*

ENV OCP_ROOT="/opt/ocp"

RUN install -o ocp -d $OCP_ROOT/install $OCP_ROOT/src

WORKDIR "$OCP_ROOT/src"

# Become user =================================================================

USER ocp:ocp

# Install Perl requirements ===================================================

ENV PATH="$OCP_ROOT/install/perl5/bin:${PATH}"
ENV PERL5LIB="$OCP_ROOT/install/perl5/lib/perl5"
ENV PERL_LOCAL_LIB_ROOT="$OCP_ROOT/install/perl5"
ENV PERL_MB_OPT="--install_base $OCP_ROOT/install/perl5"
ENV PERL_MM_OPT="INSTALL_BASE=$OCP_ROOT/install/perl5"
ENV PERL_CARTON_PATH="$OCP_ROOT/install/perl5"

# Copy cpanfile first for layer caching
COPY --chown=ocp:ocp ./cpanfile $OCP_ROOT/src

# Install all dependencies from CPAN
RUN cpm install --cpanfile=./cpanfile \
  --workers=$(nproc) --local-lib-contained=$PERL_LOCAL_LIB_ROOT \
  --show-build-log-on-failure && rm -rf ~/.perl-cpm/ /tmp/*

# Generate VERSION ------------------------------------------------------------

RUN echo -n $VERSION >VERSION

# Adding project to final stage -----------------------------------------------

FROM ocp-base AS ocp

# Copy OCP source
COPY --chown=ocp:ocp ./lib $OCP_ROOT/src/lib
COPY --chown=ocp:ocp ./bin $OCP_ROOT/src/bin
COPY --chown=ocp:ocp ./share $OCP_ROOT/src/share

# Add bin to PATH
ENV PATH="$OCP_ROOT/src/bin:${PATH}"

# Project mount point
VOLUME /project
WORKDIR /project

ENTRYPOINT ["ocp"]
CMD ["--help"]
