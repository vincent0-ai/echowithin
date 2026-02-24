FROM python:3.12-slim
ENV TZ=Africa/Nairobi
RUN apt-get update && apt-get install -y tzdata curl wget && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure -f noninteractive tzdata
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_APP=main.py
ENV FLASK_DEBUG=0
CMD ["honcho", "start"]
