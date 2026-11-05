FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
RUN mkdir -p /data
EXPOSE 21114
CMD ["python", "-u", "server.py"]
