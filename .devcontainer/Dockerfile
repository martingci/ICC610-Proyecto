FROM mcr.microsoft.com/devcontainers/python:3.14-bookworm

# Python env
RUN apt-get update && apt-get install -y python3-venv

# Node.JS 
RUN rm -f /etc/apt/sources.list.d/yarn.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

## Aditional packages for the project

# Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# CodeQL CLI
RUN curl -sSfL https://github.com/github/codeql-cli-binaries/releases/download/v2.27.0/codeql-linux64.zip -o /tmp/codeql.zip \
    && unzip -q /tmp/codeql.zip -d /usr/local \
    && chmod +x /usr/local/codeql/codeql \
    && ln -s /usr/local/codeql/codeql /usr/local/bin/codeql \
    && rm /tmp/codeql.zip


# CodeQL CLI - Packages
RUN codeql pack download codeql/python-queries \
    && codeql pack download codeql/javascript-queries \
    && codeql pack download codeql/java-queries \
    && codeql pack download codeql/actions-queries 

# Check versions of installed tools
RUN echo "CodeQL version:" && codeql version \
    && echo "Grype version:" && grype version \
    && echo "Node.js version:" && node --version \
    && echo "npm version:" && npm --version
