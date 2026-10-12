FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libyara-dev \
    build-essential \
    wget \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# Install libicu for PowerShell/.NET globalization support
# Detects the correct version at build time (libicu67 on Debian 11, libicu72 on Debian 12)
RUN apt-get update \
    && ICU_PKG=$(apt-cache search --names-only '^libicu[0-9]+$' | awk '{print $1}' | sort -V | tail -1) \
    && apt-get install -y $ICU_PKG \
    && rm -rf /var/lib/apt/lists/*

# Install PowerShell (required for PSRule Bicep scanning)
# Install directly from GitHub tarball to avoid the Microsoft APT repo SHA1 key issue
RUN curl -sL https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-x64.tar.gz \
    -o /tmp/powershell.tar.gz \
    && mkdir -p /opt/microsoft/powershell/7 \
    && tar -xzf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 \
    && chmod +x /opt/microsoft/powershell/7/pwsh \
    && ln -sf /opt/microsoft/powershell/7/pwsh /usr/local/bin/pwsh \
    && rm /tmp/powershell.tar.gz

# Install PSRule.Rules.Azure PowerShell module
# PSRule core pinned to 2.9.0. PSRule.Rules.Azure uses latest (1.38.2 never existed on PSGallery).
# Array-bounds crash is mitigated by our two-phase approach: pre-compile .bicep→ARM JSON
# with `bicep build` and scan ARM JSON with AZURE_BICEP_FILE_EXPANSION: false.
RUN pwsh -Command "\
    Install-Module -Name PSRule -RequiredVersion 2.9.0 -Force -Scope AllUsers -Repository PSGallery; \
    Install-Module -Name PSRule.Rules.Azure -Force -Scope AllUsers -Repository PSGallery\
"

# Install Bicep CLI (required by PSRule.Rules.Azure to expand .bicep files)
RUN curl -sLo /usr/local/bin/bicep https://github.com/Azure/bicep/releases/latest/download/bicep-linux-x64 \
    && chmod +x /usr/local/bin/bicep

# Install OPA
RUN curl -L -o opa https://openpolicyagent.org/downloads/v1.7.1/opa_linux_amd64 \
    && chmod +x opa \
    && mv opa /usr/local/bin/opa

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Use uv to install requirements
RUN uv pip install --system \
    --index-strategy unsafe-best-match \
    --extra-index-url https://download.pytorch.org/whl/cu124 \
    -r requirements.txt
# Copy the entire project
COPY . .

# Create necessary directories
RUN mkdir -p /app/repos /app/output /app/logs

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
