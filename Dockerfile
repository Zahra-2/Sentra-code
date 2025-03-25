# Use the official Python image with Alpine Linux for a lightweight container
FROM python:3.10-alpine  

# Set the working directory inside the container
WORKDIR /app  

# Update system packages and install required dependencies
RUN apk update && apk add --no-cache \
    bash \               # Shell for running scripts
    nmap \               # Network scanning tool
    nmap-scripts \       # Additional scripts for nmap
    gcc \                # C compiler for building dependencies
    musl-dev \           # Minimal C standard library
    libffi-dev \         # Foreign Function Interface library
    openssl-dev \        # OpenSSL development libraries
    python3-dev \        # Python development headers
    py3-pip \            # Python package manager
    cargo \              # Rust package manager (needed for some dependencies)
    rust                 # Rust language for building certain Python dependencies  

# Upgrade pip, setuptools, and wheel to avoid compatibility issues
RUN pip install --upgrade pip setuptools wheel  

# Copy the requirements file and install dependencies
COPY requirements.txt /app/  
RUN pip install --no-cache-dir -r requirements.txt  

# Copy the rest of the application files to the container
COPY . /app/  

# Expose port 8080 for incoming connections
EXPOSE 8080  

# Run the FastAPI application using Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
