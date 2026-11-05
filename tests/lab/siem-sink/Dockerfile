FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
RUN mkdir -p /data
EXPOSE 514/udp 8088/tcp
CMD ["python", "-u", "server.py"]
