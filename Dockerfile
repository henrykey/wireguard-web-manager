FROM python:3.11-slim

ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}


WORKDIR /app

# Install necessary tools
RUN apt-get update && apt-get install -y wireguard iproute2 qrencode && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# Move HTML to templates folder
RUN mkdir -p /app/templates && mv /app/index.html /app/templates/index.html

EXPOSE 8080

CMD ["python", "app.py"]
