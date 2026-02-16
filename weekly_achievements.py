import datetime
import os
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    try:
        return os.environ[name]
    except KeyError:
        message = f"Expected environment variable '{name}' not set."
        raise Exception(message)

# MongoDB connection
client = MongoClient(get_env_variable('MONGODB_CONNECTION'))
db = client['echowithin_db']
users_conf = db['users']
posts_conf = db['posts']
comments_conf = db['comments']
logs_conf = db['logs']
weekly_winners_conf = db['weekly_winners']

def calculate_weekly_winners():
    """Calculates winners for the past 7 days and updates the database."""
    now = datetime.datetime.now(datetime.timezone.utc)
    one_week_ago = now - datetime.timedelta(days=7)
    
    # 1. Most Active (Most platform activity - visits/interactions)
    # We filter user_identifier that are valid ObjectIds (registered users)
    most_active = list(logs_conf.aggregate([
        {'$match': {
            'timestamp': {'$gte': one_week_ago},
            'user_identifier': {'$regex': '^[0-9a-fA-F]{24}$'} # Rough check for ObjectId string
        }},
        {'$group': {'_id': '$user_identifier', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 1}
    ]))
    
    # Enrich most_active with username
    if most_active:
        user_doc = users_conf.find_one({'_id': ObjectId(most_active[0]['_id'])})
        most_active[0]['username'] = user_doc['username'] if user_doc else 'Unknown'
    
    # 2. Most Engager (Most comments written on blog posts)
    most_engager = list(comments_conf.aggregate([
        {'$match': {'timestamp': {'$gte': one_week_ago}}},
        {'$group': {'_id': '$author_id', 'username': {'$first': '$author_name'}, 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 1}
    ]))
    
    # 3. Top Contributor (Most total likes received on posts created this week)
    top_contributor = list(posts_conf.aggregate([
        {'$match': {'timestamp': {'$gte': one_week_ago}}},
        {'$group': {
            '_id': '$author_id', 
            'username': {'$first': '$author'}, 
            'total_likes': {'$sum': '$likes_count'}
        }},
        {'$sort': {'total_likes': -1}},
        {'$limit': 1}
    ]))
    
    winners_doc = {
        'week_end': now,
        'week_start': one_week_ago,
        'winners': {
            'most_active': most_active[0] if most_active else None,
            'most_engager': most_engager[0] if most_engager else None,
            'top_contributor': top_contributor[0] if top_contributor else None
        },
        'created_at': now
    }
    
    # Save to database
    weekly_winners_conf.insert_one(winners_doc)
    print(f"Weekly winners calculated for {one_week_ago.date()} to {now.date()}")
    return winners_doc

if __name__ == "__main__":
    calculate_weekly_winners()
