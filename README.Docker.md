# DPYPROXY Docker Image

## Overview

This Docker image sets up a simple proxy server using `dpyproxy`. It allows you to proxy requests to external websites and test the functionality.

## Prerequisites

Make sure you have Docker installed on your system. You can download Docker from [https://www.docker.com/](https://www.docker.com/).

## Build Docker Image

```bash
docker build -t dpyproxy .
```

## Run Docker Container
```bash
docker run -it -p 4433:4433 dpyproxy
```
This command runs the dpyproxy container and maps port 4433 on your host to port 4433 on the container.

## Test with cURL

After the container is running, you can test it using cURL in your host terminal.

```bash
curl -p localhost:4433 https://www.wikipedia.org
```

This command sends a request to the proxy server running on port 4433, forwarding the request to Docker container localhost:4433.