"""
Serves the "Access Restricted" block page over both HTTPS (443) and HTTP
(80) on 127.0.0.1 -- this is what a browser actually reaches when the
hosts file redirects a blocked domain here. Uses SNI (Server Name
Indication) to pick the right per-domain certificate, generated and
signed by our local CA (see block_pki.py), so the browser shows the
block page cleanly instead of a certificate warning.

Runs in background threads, started once at social_media_blocker.py's
startup and left running continuously -- harmless when nothing is
redirected here, since nothing will connect to 127.0.0.1 for a given
domain unless the hosts file currently points it there.
"""
import http.server
import socket
import ssl
import sys
import threading

import block_pki

BLOCK_PAGE_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Access Restricted</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #14161f; color: #e8e8ec;
         display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { text-align: center; max-width: 420px; padding: 40px; }
  .icon { font-size: 48px; margin-bottom: 16px; }
  h1 { font-size: 22px; margin: 0 0 12px 0; }
  p { color: #9a9aa5; font-size: 14px; line-height: 1.5; margin: 8px 0; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">&#128683;</div>
    <h1>Access Restricted</h1>
    <p>Your administrator has denied access to this site during working hours.</p>
    <p>This restriction is enforced by your organization's monitoring system.</p>
  </div>
</body>
</html>
"""


class _BlockPageHandler(http.server.BaseHTTPRequestHandler):
    def _serve(self):
        body = BLOCK_PAGE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def log_message(self, format, *args):
        pass  # suppress per-request console spam; social_media_blocker.py logs state changes instead


def _build_https_context(domains) -> ssl.SSLContext:
    cert_paths = block_pki.ensure_leaf_certs(domains)

    domain_contexts = {}
    for domain, pem_path in cert_paths.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pem_path)
        domain_contexts[domain] = ctx
        domain_contexts[f"www.{domain}"] = ctx

    def sni_callback(sslsocket, server_hostname, initial_context):
        ctx = domain_contexts.get(server_hostname)
        if ctx is not None:
            sslsocket.context = ctx
        # else: leave the default/fallback context in place (unknown SNI name --
        # still serves the block page, just with a cert that won't match that
        # particular hostname; this only happens for a domain we weren't asked
        # to cover, which shouldn't occur since hosts file only redirects
        # domains from this same list here).

    base_domain = next(iter(cert_paths)) if cert_paths else None
    base_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if base_domain:
        base_context.load_cert_chain(cert_paths[base_domain])
    base_context.sni_callback = sni_callback
    return base_context


def _serve_forever(server: http.server.HTTPServer, label: str):
    try:
        server.serve_forever()
    except Exception as e:
        print(f"Block page server ({label}) stopped: {e}", file=sys.stderr)


def start_block_page_servers(domains) -> list:
    """Starts the HTTPS (443) and HTTP (80) block-page servers as daemon
    threads. Returns the list of threads started (empty entries are
    skipped if a port couldn't be bound, e.g. already in use -- this is
    logged but doesn't stop the rest of the script from running; hosts-file
    blocking still works even if the fancy block page can't bind)."""
    block_pki.ensure_root_ca_installed()

    threads = []

    # HTTPS on 443 -- this is what actually matters, since virtually every
    # social media site is HTTPS-only.
    try:
        https_context = _build_https_context(domains)
        httpd = http.server.HTTPServer(("127.0.0.1", 443), _BlockPageHandler)
        httpd.socket = https_context.wrap_socket(httpd.socket, server_side=True)
        t = threading.Thread(target=_serve_forever, args=(httpd, "HTTPS:443"), daemon=True)
        t.start()
        threads.append(t)
        print("Block page server listening on https://127.0.0.1:443")
    except OSError as e:
        print(
            f"Could not start the HTTPS block page server on port 443: {e}. "
            f"Blocked HTTPS sites will show a browser connection error instead of "
            f"the custom block page, but hosts-file blocking itself still works.",
            file=sys.stderr,
        )

    # Plain HTTP on 80 too, for the rare case a blocked domain is reached
    # over http:// directly.
    try:
        http_httpd = http.server.HTTPServer(("127.0.0.1", 80), _BlockPageHandler)
        t2 = threading.Thread(target=_serve_forever, args=(http_httpd, "HTTP:80"), daemon=True)
        t2.start()
        threads.append(t2)
        print("Block page server listening on http://127.0.0.1:80")
    except OSError as e:
        print(f"Could not start the HTTP block page server on port 80: {e}", file=sys.stderr)

    return threads
