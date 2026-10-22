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
  libpkgconf-dev age \
  && sed -i 's/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen && locale-gen \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8

# The README's alias hands the host's LANG in (-e LANG), so `ocp init` can give
# the cluster the operator's locale (OCP::Cmd::Init::_detect_locale). That
# locale is a name for the nodes, not for this container, which generates
# en_US.UTF-8 only: every perl here -- ocp, and the rex it starts for each
# task -- greeted the operator with "perl: warning: Setting locale failed"
# before a line of OCP ran (k226). PERL_BADLANG=0 silences exactly that
# warning; perl falls back to the C locale, as it did all along. Generating
# every locale instead (locales-all) would grow the image for a warning.
ENV PERL_BADLANG=0

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

# Install sops ================================================================
# Operator tool, like kubectl: OCP reads and writes its SOPS files itself
# (File::SOPS, Crypt::Age), but a Leitstand added with `ocp keys recipients add`
# checks its access with `sops -d kubeconfig.yaml` (k212), and `age` comes from
# Debian above. Debian has no sops; the release binary is pinned by version
# and sha256 per architecture.
ARG SOPS_VERSION=3.13.3
RUN ARCH="$(dpkg --print-architecture)" \
  && case "$ARCH" in \
       amd64) SUM=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b ;; \
       arm64) SUM=53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77 ;; \
       *) echo "no pinned sops for $ARCH" >&2; exit 1 ;; \
     esac \
  && curl -fsSL -o /usr/local/bin/sops "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.${ARCH}" \
  && echo "${SUM}  /usr/local/bin/sops" | sha256sum -c - \
  && chmod +x /usr/local/bin/sops

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

# Vendored sibling dists (k222) ===============================================
# Unreleased fixes in sibling dists ship without waiting for CPAN: `make vendor`
# dzil-builds the Makefile's VENDOR list into vendor/ and names the tarballs,
# in install order, in vendor/ORDER. They go into the same contained local-lib
# FIRST, so the snapshot pass below finds them already satisfied; their own
# dependencies resolve from cpanfile.snapshot, MetaDB only as fallback. An
# empty vendor/ (`make vendor VENDOR=`) installs nothing.
COPY --chown=ocp:ocp ./vendor/ $OCP_ROOT/src/vendor/
RUN if [ -s vendor/ORDER ]; then \
      while read -r tgz; do \
        [ -n "$tgz" ] || continue; \
        echo "[vendor] $tgz"; \
        cpm install --no-test --show-build-log-on-failure --resolver snapshot --resolver metadb \
          --local-lib-contained=$PERL_LOCAL_LIB_ROOT "./vendor/$tgz" || exit 1; \
      done < vendor/ORDER; \
    fi \
 && rm -rf ~/.perl-cpm/ /tmp/*

# Install all dependencies from CPAN
#
# --configure-timeout: cpm gives a Makefile.PL 60s by default. IO-Tty's symbol
# probe compiles one test program per constant and needs longer when
# $(nproc) workers share a slow builder (rootless Podman on reuben timed out
# twice, 2026-10-22).
RUN cpm install --cpanfile=./cpanfile --snapshot=./cpanfile.snapshot \
  --workers=$(nproc) --local-lib-contained=$PERL_LOCAL_LIB_ROOT \
  --configure-timeout=600 \
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

# Cluster mount point
VOLUME /ocp
WORKDIR /ocp

ENTRYPOINT ["ocp"]
CMD ["--help"]
