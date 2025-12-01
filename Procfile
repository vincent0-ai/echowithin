web: gunicorn -w 4 -b 0.0.0.0:8000 main:app
worker: rq worker --url redis://:Developer@EchoWithin.@srv-captain--echoredis:6379 default
scheduler: python scheduler.py
