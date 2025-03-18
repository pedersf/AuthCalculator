# Use a lightweight Python image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy the files
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8080
EXPOSE 8080

# Run the app
CMD ["python", "main.py"]