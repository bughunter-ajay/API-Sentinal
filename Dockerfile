# ==============================================================================
# Dockerfile: Unified Security Scanner (Nuclei & Nikto)
# Base: Ubuntu 24.04 LTS Noble (Multi-arch: amd64 / arm64)
# ==============================================================================

FROM ubuntu:24.04

LABEL maintainer="Security QA Team"
LABEL description="Unified Vulnerability Assessment Pipeline (Nuclei & Nikto)"

# Set non-interactive debian frontend & standard environment
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH="/usr/local/bin:${PATH}"

# 1. Install Nikto, Perl, Python 3, SSL dependencies, CA certificates, and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-minimal \
    perl \
    nikto \
    libnet-ssleay-perl \
    libwhisker2-perl \
    ca-certificates \
    curl \
    wget \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 2. Install official Nuclei static binary directly for current architecture (amd64 / arm64)
ARG NUCLEI_VERSION=3.11.1
RUN ARCH="$(dpkg --print-architecture)" \
    && echo "Installing Nuclei v${NUCLEI_VERSION} for architecture: ${ARCH}" \
    && curl -fsSL -H "User-Agent: DockerfileBuild" \
       "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
       -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    && nuclei -version

# 3. Pre-download and cache Nuclei community templates during image build
# This ensures scanning works immediately even offline or behind firewalls
RUN nuclei -update-templates || true

# 4. Setup application working directory
WORKDIR /app

# Copy scanner script
COPY Nikto_Nuclei.py /app/Nikto_Nuclei.py
RUN chmod +x /app/Nikto_Nuclei.py

# Create default reports directory for volume mount
RUN mkdir -p /app/reports

# Declare volume for reports
VOLUME ["/app/reports"]

# Default environment variables
ENV TARGET_HOSTS="" \
    CONCURRENCY="2" \
    RATE_LIMIT="15" \
    TIMEOUT="7200" \
    OUTPUT_DIR="/app/reports"

# Entrypoint executes python script
ENTRYPOINT ["python3", "/app/Nikto_Nuclei.py"]

# Default CMD (empty; flags can be passed at runtime)
CMD []
