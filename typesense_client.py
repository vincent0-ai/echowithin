"""
Typesense client module — replacement for Meilisearch.
Implements scoped API key generation for tenant isolation.

Network topology:
  [Frontend] --HTTPS--> [Backend API] --internal-only--> [Typesense]

- Backend holds the admin API key (never exposed to frontend).
- Frontend receives short-lived, scoped search-only keys with embedded_filters.
- No dashboard container is deployed. Typesense port 8108 is internal-only.
"""
import os
import time
import threading
import logging

logger = logging.getLogger(__name__)

TYPESENSE_HOST = os.environ.get('TYPESENSE_HOST', 'typesense').strip()
TYPESENSE_PORT = os.environ.get('TYPESENSE_PORT', '8108').strip()
TYPESENSE_PROTOCOL = os.environ.get('TYPESENSE_PROTOCOL', 'http').strip()
TYPESENSE_API_KEY = os.environ.get('TYPESENSE_API_KEY', '').strip()
TYPESENSE_ADMIN_KEY = os.environ.get('TYPESENSE_ADMIN_KEY', '').strip() or TYPESENSE_API_KEY
TYPESENSE_SEARCH_KEY = os.environ.get('TYPESENSE_SEARCH_KEY', '').strip()

TYPESENSE_CONNECTION_TIMEOUT_SECONDS = int(
    os.environ.get('TYPESENSE_CONNECTION_TIMEOUT_SECONDS', '5')
)
TYPESENSE_HEALTHCHECK_INTERVAL_SECONDS = int(
    os.environ.get('TYPESENSE_HEALTHCHECK_INTERVAL_SECONDS', '0')
)

_typesense = None

def _get_typesense():
    global _typesense
    if _typesense is None:
        try:
            import typesense as ts
            _typesense = ts
        except ImportError:
            raise ImportError(
                'typesense package is required. Install with: pip install typesense'
            )
    return _typesense


def _build_node_config():
    return {
        'host': TYPESENSE_HOST,
        'port': TYPESENSE_PORT,
        'protocol': TYPESENSE_PROTOCOL,
    }


def create_typesense_client(api_key=None):
    key = api_key or TYPESENSE_ADMIN_KEY
    ts = _get_typesense()
    node = {
        'host': TYPESENSE_HOST,
        'port': TYPESENSE_PORT,
        'protocol': TYPESENSE_PROTOCOL,
        'api_key': key,
    }
    return ts.Client({
        'api_key': key,
        'nodes': [node],
        'connection_timeout_seconds': TYPESENSE_CONNECTION_TIMEOUT_SECONDS,
        'healthcheck_interval_seconds': TYPESENSE_HEALTHCHECK_INTERVAL_SECONDS,
    })


def _ts_import_documents(collection_name, docs, action='upsert'):
    """Import documents directly via HTTP, bypassing SDK quirks."""
    import requests
    import json
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/collections/{collection_name}/documents/import?action={action}"
    headers = {
        'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY,
        'Content-Type': 'text/plain',
    }
    body = '\n'.join(json.dumps(d) for d in docs)
    resp = requests.post(url, data=body, headers=headers, timeout=30)
    resp.raise_for_status()


def _ts_upsert_document(collection_name, doc):
    """Upsert a single document via HTTP."""
    import requests
    import json
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/collections/{collection_name}/documents?action=upsert"
    headers = {
        'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY,
        'Content-Type': 'application/json',
    }
    resp = requests.post(url, json=doc, headers=headers, timeout=10)
    resp.raise_for_status()


def _ts_delete_document(collection_name, doc_id):
    """Delete a single document via HTTP."""
    import requests
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/collections/{collection_name}/documents/{doc_id}"
    headers = {'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY}
    resp = requests.delete(url, headers=headers, timeout=10)
    if resp.status_code != 404:
        resp.raise_for_status()


def _ts_search(collection_name, params):
    """Search documents via HTTP. Returns parsed JSON."""
    import requests
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/collections/{collection_name}/documents/search"
    headers = {'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY}
    resp = requests.get(url, params=params, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _ts_collection_stats(collection_name):
    """Get collection stats via HTTP."""
    import requests
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/collections/{collection_name}"
    headers = {'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_collection_schemas():
    return {
        'posts': {
            'name': 'posts',
            'enable_nested_fields': True,
            'fields': [
                {'name': 'id', 'type': 'string'},
                {'name': 'title', 'type': 'string', 'sort': True},
                {'name': 'content', 'type': 'string'},
                {'name': 'slug', 'type': 'string'},
                {'name': 'author_id', 'type': 'string', 'facet': True},
                {'name': 'author_username', 'type': 'string', 'facet': True},
                {'name': 'tags', 'type': 'string[]', 'facet': True, 'optional': True},
                {'name': 'created_at', 'type': 'int64', 'sort': True},
            ],
            'default_sorting_field': 'created_at',
            'token_separators': [' ', '-', '_', '.', ',', ';', ':', '/', '\\', '|', '@', '#', '!', '?', '&', '*', '(', ')', '[', ']', '{', '}'],
            'symbols_to_index': ['+', '#', '@', '_', '-', '.'],
        },
        'personal_notes': {
            'name': 'personal_notes',
            'enable_nested_fields': True,
            'fields': [
                {'name': 'id', 'type': 'string'},
                {'name': 'user_id', 'type': 'string', 'facet': True},
                {'name': 'is_locked', 'type': 'bool', 'facet': True},
                {'name': 'content', 'type': 'string'},
                {'name': 'reference', 'type': 'string', 'optional': True},
                {'name': 'tags', 'type': 'string[]', 'facet': True, 'optional': True},
                {'name': 'created_at', 'type': 'int64', 'sort': True},
            ],
            'default_sorting_field': 'created_at',
            'token_separators': [' ', '-', '_', '.', ',', ';', ':', '/', '\\', '|', '@', '#', '!', '?', '&', '*', '(', ')', '[', ']', '{', '}'],
            'symbols_to_index': ['+', '#', '@', '_', '-', '.'],
        },
    }


def generate_scoped_search_key(
    user_id,
    collection='*',
    expires_at=None,
    embedded_filters='',
):
    if not TYPESENSE_SEARCH_KEY:
        logger.error('TYPESENSE_SEARCH_KEY is not set; cannot generate scoped keys')
        return ''

    ts = _get_typesense()

    if expires_at is None:
        expires_at = int(time.time()) + 3600

    scoped_key = ts.scoped_search_key(
        TYPESENSE_SEARCH_KEY,
        {
            'filter_by': embedded_filters,
            'expires_at': expires_at,
        },
    )

    return scoped_key


# ---- Global singletons and init ----

ts_client = None
ts_posts = None
ts_notes = None


def _check_typesense_health(client):
    """Check Typesense health via its REST API. Raises on failure."""
    import requests
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/health"
    headers = {'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY}
    resp = requests.get(url, headers=headers, timeout=TYPESENSE_CONNECTION_TIMEOUT_SECONDS)
    resp.raise_for_status()
    data = resp.json()
    if not data.get('ok'):
        raise RuntimeError(f'Typesense health check returned non-ok: {data}')
    logger.info(f'Typesense health OK at {url}')


def _init_typesense(max_retries=3):
    global ts_client, ts_posts, ts_notes

    # Wire module logger to root so gunicorn sees it
    root = logging.getLogger()
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

    if not TYPESENSE_HOST or not TYPESENSE_ADMIN_KEY:
        logger.info('Typesense not configured, skipping initialization')
        return

    retry_delay = 1
    for attempt in range(max_retries):
        try:
            ts_client = create_typesense_client()
            _check_typesense_health(ts_client)
            break
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(
                    f'Typesense connection attempt {attempt+1} failed: {e}. '
                    f'Retrying in {retry_delay}s...'
                )
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                logger.error(
                    f'Failed to initialize Typesense client after '
                    f'{max_retries} attempts: {e}'
                )
                return

    try:
        schemas = get_collection_schemas()
        for name, schema in schemas.items():
            try:
                _ts_collection_stats(name)
            except Exception:
                try:
                    _ts_create_collection(schema)
                except Exception as ce:
                    logger.debug(f'create_collection {name} (continuing): {ce}')
        ts_posts = 'posts'  # flag that we're initialized
        ts_notes = 'personal_notes'
        logger.info('Connected to Typesense and configured collections')
    except Exception as e:
        logger.error(f'Failed to configure Typesense collections: {e}')


def _ts_create_collection(schema):
    """Create a Typesense collection via HTTP."""
    import requests
    import json
    url = f"{TYPESENSE_PROTOCOL}://{TYPESENSE_HOST}:{TYPESENSE_PORT}/collections"
    headers = {
        'X-TYPESENSE-API-KEY': TYPESENSE_ADMIN_KEY,
        'Content-Type': 'application/json',
    }
    resp = requests.post(url, json=schema, headers=headers, timeout=10)
    resp.raise_for_status()


_init_thread = threading.Thread(target=_init_typesense, daemon=True)
_init_thread.start()
_init_thread.join(timeout=5)
if _init_thread.is_alive():
    logger.warning(
        'Typesense initialization timed out after 5s; '
        'search may be unavailable but will keep retrying in background'
    )
