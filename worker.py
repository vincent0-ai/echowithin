from gevent import monkey
monkey.patch_all()

from urllib.parse import urlparse
import os
import redis
from rq import Worker, Queue
import dotenv

dotenv.load_dotenv(override=True)

listen = ['default']

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
if not redis_url.startswith('redis://') and not redis_url.startswith('rediss://'):
    redis_url = f'redis://{redis_url}'
    
try:
    conn = redis.from_url(redis_url)
    # Check if we can actually reach the server before spinning up the worker
    conn.ping()
except Exception as e:
    print(f"Redis string connection error, falling back: {e}")
    conn = redis.Redis(host='localhost', port=6379)

if __name__ == '__main__':
    # Disable ConnectionError logging loop so we can quickly exit or run locally
    try:
        worker = Worker([Queue(name, connection=conn) for name in listen], connection=conn)
        worker.work()
    except redis.exceptions.ConnectionError:
        print("Warning: Redis service completely unreachable. Worker suspended.")
