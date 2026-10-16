"""Key custody for at-rest encryption.

Data keys (user DEKs, DM conversation DEKs, the media-at-rest key) are wrapped
by a root mechanism resolved from a custody ladder, highest priority first:

  1. Vault Transit — enabled by VAULT_TRANSIT_KEY. Data keys are wrapped and
     unwrapped *inside* Vault; the key material never leaves Vault and cannot be
     read back.
  2. Vault KV — enabled by VAULT_MASTER_KEY_PATH. A master key value is stored
     in Vault and fetched once at startup.
  3. MASTER_KEY environment variable.
  4. Legacy fallback: the Flask SECRET_KEY — transition mode only, so keys
     wrapped before a root key was configured keep working.

No key material is ever hardcoded or defaulted here. If a Vault-backed mode is
selected but misconfigured or unreachable, this raises instead of silently
downgrading.
"""

import base64
import logging
import os

import requests

logger = logging.getLogger(__name__)

_VAULT_HTTP_TIMEOUT = 10  # seconds


# --- Vault transport helpers ---

def _vault_conn():
    """Return (addr, token, namespace) for Vault, failing fast if unset."""
    addr = os.environ.get('VAULT_ADDR', '').strip()
    token = os.environ.get('VAULT_TOKEN', '').strip()
    if not (addr and token):
        raise Exception('VAULT_ADDR and VAULT_TOKEN must both be set to use Vault.')
    namespace = os.environ.get('VAULT_NAMESPACE', '').strip() or None
    return addr, token, namespace


def _vault_headers(token, namespace):
    headers = {'X-Vault-Token': token}
    if namespace:
        headers['X-Vault-Namespace'] = namespace
    return headers


def _vault_read(addr, token, path, namespace):
    """Read a secret from Vault's KV store (v2 aware). Returns the data dict."""
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    resp = requests.get(url, headers=_vault_headers(token, namespace), timeout=_VAULT_HTTP_TIMEOUT)
    if resp.status_code == 404:
        raise Exception(f"Vault secret not found at path '{path}'.")
    if resp.status_code in (401, 403):
        raise Exception(f"Vault rejected the token for path '{path}' ({resp.status_code}).")
    resp.raise_for_status()

    payload = resp.json()
    data = payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise Exception(f"Unexpected Vault response for path '{path}'.")

    # KV v2 nests the secret under data.data; KV v1 keeps it directly in data.
    inner = data.get('data')
    if isinstance(inner, dict):
        return inner
    return data


def _vault_post(addr, token, path, body, namespace):
    """POST to a Vault endpoint and return its data dict."""
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    resp = requests.post(url, headers=_vault_headers(token, namespace), json=body, timeout=_VAULT_HTTP_TIMEOUT)
    if resp.status_code in (401, 403):
        raise Exception(f"Vault rejected the token for path '{path}' ({resp.status_code}).")
    resp.raise_for_status()

    payload = resp.json()
    data = payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise Exception(f"Unexpected Vault response for path '{path}'.")
    return data


def _extract_material(source: dict, field: str):
    """Pull the key string out of a Vault secret dict and return it as bytes."""
    value = source.get(field) if isinstance(source, dict) else None
    if isinstance(value, str) and value:
        return value.encode('utf-8')
    if isinstance(value, bytes) and value:
        return value
    return None


# --- Vault Transit (key material never leaves Vault) ---

def transit_key_name():
    return os.environ.get('VAULT_TRANSIT_KEY', '').strip()


def transit_enabled() -> bool:
    return bool(transit_key_name())


def transit_encrypt(plaintext: bytes) -> str:
    """Wrap raw key bytes with Vault Transit. Returns a 'vault:vN:...' token."""
    addr, token, namespace = _vault_conn()
    body = {'plaintext': base64.b64encode(plaintext).decode('ascii')}
    data = _vault_post(addr, token, f'transit/encrypt/{transit_key_name()}', body, namespace)
    ciphertext = data.get('ciphertext')
    if not ciphertext:
        raise Exception('Vault Transit returned no ciphertext.')
    return ciphertext


def transit_decrypt(ciphertext: str) -> bytes:
    """Unwrap a 'vault:vN:...' token back to raw key bytes."""
    addr, token, namespace = _vault_conn()
    data = _vault_post(
        addr, token, f'transit/decrypt/{transit_key_name()}',
        {'ciphertext': ciphertext}, namespace
    )
    plaintext = data.get('plaintext')
    if not plaintext:
        raise Exception('Vault Transit returned no plaintext.')
    return base64.b64decode(plaintext)


# --- Root key material (KV / env / legacy) for the non-Transit KEK path ---

def get_master_key_material(secret_key_bytes: bytes) -> bytes:
    """Return the root key material (bytes) from which the KEK is derived.

    In Transit mode this is only used for the legacy fallback KEK, so it returns
    the MASTER_KEY env var if set, otherwise the SECRET_KEY. Raises on Vault KV
    misconfiguration or failure; falls back to SECRET_KEY only when no root key
    is configured (transition mode).
    """
    if transit_enabled():
        env_master = os.environ.get('MASTER_KEY', '').strip()
        return env_master.encode('utf-8') if env_master else secret_key_bytes

    path = os.environ.get('VAULT_MASTER_KEY_PATH', '').strip()
    if path:
        addr, token, namespace = _vault_conn()
        field = os.environ.get('VAULT_MASTER_KEY_FIELD', 'value').strip() or 'value'
        source = _vault_read(addr, token, path, namespace)
        material = _extract_material(source, field)
        if not material:
            raise Exception(f"Vault secret at '{path}' has no usable '{field}' field.")
        logger.info('Loaded master key from Vault path %s.', path)
        return material

    env_master = os.environ.get('MASTER_KEY', '').strip()
    if env_master:
        logger.info('Loaded master key from MASTER_KEY environment variable.')
        return env_master.encode('utf-8')

    logger.warning(
        'No Vault Transit/KV or MASTER_KEY configured; deriving KEK from SECRET_KEY '
        '(transition mode). Configure VAULT_TRANSIT_KEY or MASTER_KEY.'
    )
    return secret_key_bytes


# --- Status / self-check ---

def current_mode() -> str:
    """Human-readable label for the active key-custody mode."""
    if transit_enabled():
        return f'vault-transit ({transit_key_name()})'
    if os.environ.get('VAULT_MASTER_KEY_PATH', '').strip():
        return 'vault-kv'
    if os.environ.get('MASTER_KEY', '').strip():
        return 'master-key-env'
    return 'transition (SECRET_KEY-derived KEK)'


def verify_transit() -> bool:
    """Round-trip a throwaway value through Transit. True if healthy."""
    try:
        probe = os.urandom(32)
        return transit_decrypt(transit_encrypt(probe)) == probe
    except Exception as e:
        logger.error('Vault Transit self-check error: %s', e)
        return False


def log_startup_status(logger):
    """Log the active key-custody mode, self-checking Transit when enabled."""
    label = current_mode()
    if transit_enabled():
        if verify_transit():
            logger.info('Key custody: %s — self-check OK.', label)
        else:
            logger.error(
                'Key custody: %s — self-check FAILED. Check VAULT_ADDR/VAULT_TOKEN '
                'reachability and the transit encrypt/decrypt policy.', label
            )
    elif label.startswith('transition'):
        logger.warning('Key custody: %s.', label)
    else:
        logger.info('Key custody: %s.', label)

