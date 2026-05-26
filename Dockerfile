FROM python:3.12-slim
ENV TZ=Africa/Nairobi
RUN apt-get update && apt-get install -y tzdata curl wget && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure -f noninteractive tzdata
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_APP=main.py
ENV FLASK_DEBUG=0
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import socket; s = socket.socket(); s.settimeout(5); s.connect(('127.0.0.1', 8000)); s.close()" || exit 1
CMD ["honcho", "start"]
