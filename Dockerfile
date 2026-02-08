# ==============================
# Base Image
# ==============================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# ==============================
# System Dependencies
# ==============================
RUN apt-get update && apt-get install -y \
    software-properties-common \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    net-tools \
    iproute2 \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Avoid Wireshark permission prompt
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# ==============================
# Python 3.10 + pip
# ==============================
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y \
        python3.10 \
        python3.10-venv \
        python3.10-distutils \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Make python -> python3.10
RUN ln -sf /usr/bin/python3.10 /usr/bin/python


# ==============================
# Node.js 20 (for Vite)
# ==============================
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# ==============================
# Backend Python Dependencies
# ==============================
COPY backend/requirements.txt /app/backend/requirements.txt

RUN python3.10 -m pip install --upgrade pip && \
    python3.10 -m pip install --no-cache-dir -r /app/backend/requirements.txt

# ==============================
# Frontend Dependencies
# ==============================
COPY frontend/package.json frontend/package-lock.json /app/frontend/
WORKDIR /app/frontend
RUN npm install

# ==============================
# Copy Application Code
# ==============================
WORKDIR /app
COPY backend /app/backend
COPY frontend /app/frontend
COPY models /app/models

# ==============================
# Expose Ports
# ==============================
EXPOSE 8000
EXPOSE 5173

# ==============================
# Start Backend + Frontend
# ==============================
CMD ["bash", "-c", "\
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 & \
cd frontend && npx vite --host 0.0.0.0 --port 5173 & \
wait \
"]


