# Use the official Python image with Alpine Linux
FROM python:3.10-alpine  

# Set the working directory inside the container
WORKDIR /app  

# Update system and install required dependencies
RUN apk update && apk add --no-cache \
    bash \
    nmap \
    nmap-scripts \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    py3-pip \
    cargo \
    rust  

# Upgrade pip, setuptools, and wheel
RUN pip install --upgrade pip setuptools wheel  

# Copy requirements.txt and install dependencies
COPY requirements.txt /app/  
RUN pip install --no-cache-dir -r requirements.txt  

# Copy the rest of the application files
COPY . /app/  

# Expose port 8080 for the application
EXPOSE 8080  

# Run the FastAPI application with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
