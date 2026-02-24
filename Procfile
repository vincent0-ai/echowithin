web: gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 --timeout 120 --keep-alive 5 --worker-tmp-dir /dev/shm -b 0.0.0.0:8000 main:app
worker: python worker.py
scheduler: python scheduler.py
