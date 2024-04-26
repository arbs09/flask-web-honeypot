# Use the official Python image as a base
FROM python:3.13.0a6-slim

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the working directory
COPY . .

# Expose the port the app runs on
EXPOSE 80

# Pass the API key as a build argument
ARG API_KEY
ENV API_KEY=$API_KEY

# Run the application
CMD ["flask", "run", "--port=80"]