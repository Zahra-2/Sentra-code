# Use the official Python image from Docker Hub
FROM alpine

# Set the working directory inside the container
WORKDIR /app

RUN apk update && \
    apk add nmap && \
    apk add nmap-scripts && \
    apk add python3 && \
    apk add py3-pip
    #rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt file and install dependencies
COPY requirements.txt /app/

RUN python3 -m venv env && \
    ./env/bin/pip3 install -r requirements.txt && \
    ./env/bin/pip3 install jinja2 && \
    ./env/bin/pip3 install python-multipart

# Copy the FastAPI app
COPY . /app/

# Expose port 8080 for Cloud Run
EXPOSE 8080

# Command to run the FastAPI app with Uvicorn
CMD ["./env/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
