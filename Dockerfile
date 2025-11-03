# Dockerfile
FROM python:3.12-slim

# Install dependencies (including nmap)
RUN apt-get update && apt-get install -y nmap && apt-get clean

# Set workdir
WORKDIR /app

# Copy project files
COPY . /app

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask port
EXPOSE 5000

# Run Flask
CMD ["python", "app.py"]