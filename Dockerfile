FROM python:3.11-slim

# install tools with retries
RUN apt-get update -qq --fix-missing && \
    apt-get install -y --no-install-recommends \
        nmap tshark recon-ng git build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY reconborne.py .

ENTRYPOINT ["python3", "reconborne.py"]