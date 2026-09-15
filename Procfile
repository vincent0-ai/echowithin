web: gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 --timeout 120 --keep-alive 75 --worker-tmp-dir /dev/shm -b 0.0.0.0:8000 main:app
worker: python -u scripts/worker.py
scheduler: python -u scripts/scheduler.py
