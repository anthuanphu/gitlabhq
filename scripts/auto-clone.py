#!/usr/bin/env python3
"""Auto-clone for code-server. Receives /open?project=ns/proj, clones, redirects."""
import subprocess, os, urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

WORKSPACE = '/workspace'
GITLAB_URL = os.environ.get('GITLAB_URL', 'http://gitlab:8228')
GITLAB_TOKEN = os.environ.get('GITLAB_TOKEN', '')
CODE_URL = os.environ.get('CODE_SERVER_URL', 'http://localhost:8443')

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(p.query)
        project = params.get('project', [None])[0]
        if p.path == '/open' and project:
            folder = os.path.join(WORKSPACE, project)
            if not os.path.exists(folder):
                url = f'{GITLAB_URL}/{project}.git'
                if GITLAB_TOKEN:
                    url = f'http://oauth2:{GITLAB_TOKEN}@gitlab:8228/{project}.git'
                subprocess.run(['git', 'clone', '--depth', '1', url, folder], check=False, timeout=120)
            self.send_response(302)
            self.send_header('Location', f'{CODE_URL}/?folder={folder}')
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header('Location', f'{CODE_URL}/')
            self.end_headers()

HTTPServer(('0.0.0.0', 3000), Handler).serve_forever()
            self.send_response(302)
            self.send_header('Location', 'http://code-server:8443/')
            self.end_headers()

HTTPServer(('0.0.0.0', 3000), Handler).serve_forever()
