#!/usr/bin/env python3
"""
Dokploy Control Utility (dokploy_ctl.py)
Programmatic management of EchoWithin application deployments via Dokploy REST API.
Compatible with standard library (no external pip dependencies required).
"""

import sys
import os
import json
import urllib.request
import urllib.error
from pathlib import Path

# Load configuration from local .env if present
BASE_DIR = Path(__file__).resolve().parent.parent
env_file = BASE_DIR / '.env'
if env_file.exists():
    with open(env_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())

DOKPLOY_URL = os.getenv('DOKPLOY_URL', 'http://193.181.209.169:3000').rstrip('/')
DOKPLOY_API_KEY = os.getenv('DOKPLOY_API_KEY', '')
APPLICATION_ID = os.getenv('DOKPLOY_APP_ID', '_EYWgldNC_n-ZSCJ_N6VA')


def api_request(endpoint, data=None):
    """Execute an authenticated request to the Dokploy REST API."""
    if not DOKPLOY_API_KEY:
        print("[ERROR] DOKPLOY_API_KEY not set. Add it to .env or set as env var.",
              file=sys.stderr)
        sys.exit(1)
    url = f"{DOKPLOY_URL}{endpoint}"
    headers = {
        'x-api-key': DOKPLOY_API_KEY,
        'Accept': 'application/json'
    }
    encoded_data = None
    if data is not None:
        headers['Content-Type'] = 'application/json'
        encoded_data = json.dumps(data).encode('utf-8')

    req = urllib.request.Request(url, data=encoded_data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode('utf-8')
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode('utf-8')
        print(f"[ERROR] HTTP {e.code} for {endpoint}: {err_msg}", file=sys.stderr)
        return {'error': f"HTTP {e.code}", 'details': err_msg}
    except Exception as e:
        print(f"[ERROR] Connection failure to {url}: {e}", file=sys.stderr)
        return {'error': str(e)}


def cmd_status():
    """Display real-time application and server status."""
    print("=" * 60)
    print(f" Dokploy Infrastructure Status -> {DOKPLOY_URL}")
    print("=" * 60)

    app = api_request(f"/api/application.one?applicationId={APPLICATION_ID}")
    if 'error' in app:
        print(f"Failed to fetch application: {app}")
        return

    name = app.get('name', 'Unknown')
    app_name = app.get('appName', 'Unknown')
    status = app.get('applicationStatus', 'Unknown')
    repo = app.get('repository', 'Unknown')
    branch = app.get('branch', 'Unknown')
    auto_deploy = app.get('autoDeploy', False)

    print(f" Application Name : {name} ({app_name})")
    print(f" Application ID   : {APPLICATION_ID}")
    print(f" Status           : {status.upper()}")
    print(f" Repository       : {repo} (branch: {branch})")
    print(f" Auto-Deploy      : {'Enabled (Webhook on push)' if auto_deploy else 'Disabled'}")

    domains = app.get('domains', [])
    if domains:
        print("\n Mapped Domains & SSL:")
        for d in domains:
            host = d.get('host')
            https = d.get('https')
            port = d.get('port')
            cert = d.get('certificateType')
            print(f"   - {'https://' if https else 'http://'}{host} -> port {port} (Cert: {cert})")

    deployments = app.get('deployments', [])
    if deployments:
        latest = deployments[0]
        print("\n Latest Deployment:")
        print(f"   - Title      : {latest.get('title')}")
        print(f"   - Description: {latest.get('description')}")
        print(f"   - Status     : {latest.get('status')}")
        print(f"   - Date       : {latest.get('createdAt')}")


def cmd_deploy():
    """Trigger an immediate production deployment on Dokploy."""
    print(f"Triggering deployment for application {APPLICATION_ID}...")
    res = api_request("/api/application.deploy", {"applicationId": APPLICATION_ID})
    print(json.dumps(res, indent=2))
    print("[SUCCESS] Deployment queued in Dokploy. Monitor build via 'status' or web panel.")


def cmd_redeploy():
    """Trigger an application rebuild and redeploy."""
    print(f"Triggering redeploy for application {APPLICATION_ID}...")
    res = api_request("/api/application.redeploy", {"applicationId": APPLICATION_ID})
    print(json.dumps(res, indent=2))


def cmd_stop():
    """Stop the running application container."""
    print(f"Stopping application {APPLICATION_ID}...")
    res = api_request("/api/application.stop", {"applicationId": APPLICATION_ID})
    print(json.dumps(res, indent=2))


def cmd_containers():
    """List all Docker containers currently active on the VPS."""
    print("=" * 60)
    print(" Active Docker Containers on Host VPS")
    print("=" * 60)
    containers = api_request("/api/docker.getContainers")
    if isinstance(containers, list):
        for c in containers:
            c_name = c.get('name')
            image = c.get('image')
            status = c.get('status')
            ports = c.get('ports') or 'internal'
            print(f"- {c_name}")
            print(f"    Image : {image}")
            print(f"    Status: {status}")
            print(f"    Ports : {ports}")
    else:
        print(containers)


def cmd_env():
    """Display the active environment variables configured in Dokploy."""
    app = api_request(f"/api/application.one?applicationId={APPLICATION_ID}")
    env_str = app.get('env', '')
    print("=" * 60)
    print(" Dokploy Environment Configuration for EchoWithin")
    print("=" * 60)
    print(env_str if env_str else "(No environment variables configured)")


def cmd_projects():
    """List all projects and services hosted on this Dokploy instance."""
    projects = api_request("/api/project.all")
    print("=" * 60)
    print(" Dokploy Projects & Workspaces")
    print("=" * 60)
    if isinstance(projects, list):
        for p in projects:
            p_name = p.get('name')
            p_id = p.get('projectId')
            desc = p.get('description') or ''
            print(f"\n[Project: {p_name}] (ID: {p_id})")
            print(f" Description: {desc}")
            envs = p.get('environments', [])
            for e in envs:
                apps = e.get('applications', [])
                comp = e.get('compose', [])
                mongo = e.get('mongo', [])
                print(f"   * Environment: {e.get('name')} (Apps: {len(apps)}, Compose: {len(comp)}, Mongo: {len(mongo)})")
                for a in apps:
                    print(f"       - App: {a.get('name')} (ID: {a.get('applicationId')}, Status: {a.get('applicationStatus')})")
    else:
        print(projects)


def main():
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else 'status'
    commands = {
        'status': cmd_status,
        'deploy': cmd_deploy,
        'redeploy': cmd_redeploy,
        'stop': cmd_stop,
        'containers': cmd_containers,
        'env': cmd_env,
        'projects': cmd_projects
    }

    if cmd in commands:
        commands[cmd]()
    else:
        print(f"Unknown command: '{cmd}'")
        print(f"Available commands: {', '.join(commands.keys())}")
        sys.exit(1)


if __name__ == '__main__':
    main()
