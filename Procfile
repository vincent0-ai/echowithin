web: gunicorn -w 4 -b 0.0.0.0:8000 main:app
worker: rq worker --url $REDIS_URL default
scheduler: python scheduler.py
