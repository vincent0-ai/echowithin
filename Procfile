web: gunicorn -w 2 --threads 2 --worker-tmp-dir /dev/shm -b 0.0.0.0:8000 main:app
worker: rq worker --url $REDIS_URL default
scheduler: python scheduler.py
