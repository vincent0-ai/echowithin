web: gunicorn -k gevent -w 1 --timeout 120 --keep-alive 5 --worker-tmp-dir /dev/shm -b 0.0.0.0:8000 main:app
worker: python scripts/worker.py
scheduler: python scripts/scheduler.py
