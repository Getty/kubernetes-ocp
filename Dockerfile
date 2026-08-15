# OCP - Omni Control Plane Docker Image
# Build: docker build -t ocp .
# Use:   docker run -v $(pwd):/ocp ocp status

# The base is the official Perl image rather than a Perl built from source in
# this Dockerfile. Why that swap is safe: this perl is non-threaded and
# 64-bit-all — the two settings that decide XS ABI compatibility — exactly like
# the `Configure -des` build it replaces, and every XS module in the image is
# compiled against it right here, so no binary crosses an ABI boundary. It
# differs only in useshrplib (shared libperl, what every distro perl does) and
# in being a newer maintenance release of the same 5.42.
#
# It is pinned to an exact patch version, which nails the artifact down as
# precisely as the tarball's sha256 used to (ADR 0014), and the tag resolves
# to the architecture of the machine doing the build.
#
# It also closes a gap: `make snapshot` already resolves cpanfile.snapshot in
# `perl:5.42` — same 5.42.3, same non-threaded shared-libperl build. The
# source-built 5.42.0 was the odd perl out, so the snapshot described a world
# the shipped image did not run in, which is exactly what ADR 0013 forbids.
FROM perl:5.42.3-slim-trixie AS ocp-base
ARG VERSION="develop"

ENV DEBIAN_FRONTEND="noninteractive"

ARG OCP_UID=1000
ARG OCP_GID=1000

# Install Base Packages ======================================================

RUN apt-get update -y && apt-get install -y --no-install-recommends \
  curl ca-certificates git openssh-client locales \
  libexpat1-dev zlib1g-dev libssl-dev libssh-dev build-essential pkg-config libtool libtool-bin \
  libpkgconf-dev \
  && sed -i 's/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen && locale-gen \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8

# Install kubectl =============================================================
# Debug tool only. OCP itself never shells out to kubectl — all Kubernetes
# access goes through Kubernetes::REST / IO::K8s. This is here so you can
# poke at the cluster from inside the image.

#
# The architecture comes from dpkg: it is whatever the image is being built
# for, so kubectl always matches the rest of the image. A hardcoded amd64 here
# would put an unrunnable binary into an image built on an arm64 machine.
RUN ARCH="$(dpkg --print-architecture)" \
  && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl" \
  && chmod +x kubectl \
  && mv kubectl /usr/local/bin/

# Perl toolchain ==============================================================
# The base image already carries perl, cpanm, cpm and a working
# Net::SSLeay/IO::Socket::SSL, so the bootstrap is down to the single module cpm
# needs in order to read a cpanfile.snapshot at all.
#
# Nothing else goes into the system perl. What OCP actually runs is declared in
# cpanfile and installed into the contained local-lib below, where the snapshot
# describes it — LWP::Protocol::https included. That one used to be cpanm'd in
# here, behind the snapshot's back and with the full test suite of every
# dependency, which made it the slowest layer in the build.

RUN cpm install --global --no-test --show-build-log-on-failure Carton::Snapshot \
  && rm -rf ~/.perl-cpm /tmp/*

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
COPY --chown=ocp:ocp ./cpanfile.snapshot $OCP_ROOT/src

# Install all dependencies from CPAN
RUN cpm install --cpanfile=./cpanfile --snapshot=./cpanfile.snapshot \
  --workers=$(nproc) --local-lib-contained=$PERL_LOCAL_LIB_ROOT \
  --show-build-log-on-failure && rm -rf ~/.perl-cpm/ /tmp/*

# Apply local patches over installed CPAN modules.
# TODO: drop this once Rex::Interface::Connection::LibSSH 0.004 is released
# and pinned in cpanfile + snapshot. Until then this overlays our local fix
# for the env-handling bug in Rex::Interface::Exec::LibSSH (3-arg signature
# + shell-based env wrapping) directly into the installed module path.
COPY --chown=ocp:ocp ./share/patches/ $PERL_LOCAL_LIB_ROOT/lib/perl5/

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

# Cluster mount point
VOLUME /ocp
WORKDIR /ocp

ENTRYPOINT ["ocp"]
CMD ["--help"]
