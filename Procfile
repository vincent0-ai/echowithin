web: gunicorn -k gevent -w 1 --threads 4 --timeout 120 --keep-alive 5 --worker-tmp-dir /dev/shm -b 0.0.0.0:8000 main:app
worker: rq worker --url $REDIS_URL default
scheduler: python scheduler.py
