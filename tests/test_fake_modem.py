"""Fake modem test: connection reuse, logout, timeouts, poll budget, host lock.

Run with: python tests/test_fake_modem.py  (needs requests and pycryptodome)
"""
import importlib, json, os, socket, sys, threading, time, types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    import Crypto  # noqa: F401  pycryptodome
except ImportError:  # pycryptodomex installs as Cryptodome
    for n in ["", ".Cipher", ".Util", ".Util.Padding", ".PublicKey"]:
        sys.modules["Crypto" + n] = importlib.import_module("Cryptodome" + n)
# Load api.py and the vendored nr7101 without Home Assistant.
pkg = types.ModuleType("zyx"); pkg.__path__ = [os.path.join(ROOT, "custom_components", "ha_zyxel")]
sys.modules["zyx"] = pkg
api = importlib.import_module("zyx.api")
import requests

conns, hits, cookies_seen = [], [], []
SLOW = set()
TRICKLE = set()
DRIP = set()      # Content-Length dichiarato, un byte alla volta
STALL = set()     # header inviati, corpo mai
LOGIN_GATE = threading.Event(); LOGIN_GATE.set()
GZIP = set()          # il modem comprime anche se gli si chiede di no
LOGOUT_DRIP = []      # il modem risponde all'uscita a gocce
encodings = []

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def setup(self):
        super().setup(); conns.append(1)
    def log_message(self, *a): pass
    def _send(self, obj, cookie=None):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); hits.append(u.path + "?" + u.query)
        cookies_seen.append(self.headers.get("Cookie"))
        encodings.append(self.headers.get("Accept-Encoding"))
        if u.path == "/GetInfoNoLogin": return self._send({}, "Session=abc; Path=/")
        if u.path == "/getRSAPublickKey": return self._send({"RSAPublicKey": "None"})
        if u.path == "/cgi-bin/UserLogout":
            if LOGOUT_DRIP:
                self.send_response(200); self.send_header("Content-Length", "1000"); self.end_headers()
                try:
                    for _ in range(1000): self.wfile.write(b" "); self.wfile.flush(); time.sleep(0.3)
                except (BrokenPipeError, ConnectionResetError): pass
                self.close_connection = True; return
            return self._send({"result": "ZCFG_SUCCESS"})
        if u.path == "/cgi-bin/DAL":
            oid = parse_qs(u.query)["oid"][0]
            if oid in GZIP:
                import gzip as _gz
                b = _gz.compress(json.dumps({"result": "ZCFG_SUCCESS", "Object": [{"oid": oid}]}).encode())
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Encoding", "gzip"); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b); return
            if oid in DRIP or oid in STALL:
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "100"); self.end_headers(); self.wfile.flush()
                try:
                    for _ in range(100):
                        if oid in DRIP: self.wfile.write(b" "); self.wfile.flush()
                        time.sleep(0.3)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True; return
            if oid in TRICKLE:  # risposta lunga mandata a pezzetti, ognuno sotto il limite
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
                try:
                    for _ in range(40):
                        self.wfile.write(b"1\r\n \r\n"); self.wfile.flush(); time.sleep(0.5)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True; return
                return
            if oid in SLOW: time.sleep(3 if len(SLOW) == 1 else 0.8)
            return self._send({"result": "ZCFG_SUCCESS", "Object": [{"oid": oid, "Index": 1, "wlEnable": True}]}, "Junk=zzz; Path=/")
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        hits.append("PUT " + self.path)
        return self._send({"result": "ZCFG_SUCCESS"})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        hits.append(self.path)
        LOGIN_GATE.wait()
        return self._send({"sessionkey": "k1"})

ThreadingHTTPServer.handle_error = lambda *a: None  # clients that time out on purpose
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}"

# A. una sola connessione per i polling
r = api.create_router(url, "admin", "pw")
data = api.fetch_status(r)
assert "device" in data and "nat_rules" in data and "wlan_ssids" in data, data.keys()
conns.clear(); hits.clear()
api.fetch_status(r)
dal = [h for h in hits if h.startswith("/cgi-bin/DAL")]
print(f"A. secondo polling: {len(dal)} richieste, {len(conns)} connessioni")
assert len(dal) == 10 and len(conns) <= 1
# F. cookie: il jar della sessione resta vuoto, il cookie di login viene ancora inviato
assert len(r.ha_zyxel_session.cookies) == 0 and all("Session=abc" in (c or "") for c in cookies_seen[-10:])
print("F. cookie invariati: ok")

# B. logout alla chiusura
hits.clear(); api.close_router(r)
assert any(h.startswith("/cgi-bin/UserLogout") for h in hits) and r.sessionkey is None
print("B. logout alla chiusura: ok")

# C. router che accetta e non risponde: create_router non resta appeso
api.REQUEST_TIMEOUT = (1, 1); api.SETUP_TIMEOUT = (1, 1)
mute = socket.socket(); mute.bind(("127.0.0.1", 0)); mute.listen(5)
t = time.time()
try:
    api.create_router(f"http://127.0.0.1:{mute.getsockname()[1]}", "admin", "pw"); raise SystemExit("C. nessun errore")
except requests.exceptions.Timeout:
    print(f"C. router muto: errore dopo {time.time()-t:.1f} s")

# D. un endpoint lento ferma il polling, gli altri non vengono chiesti
r = api.create_router(url, "admin", "pw"); api.fetch_status(r)
SLOW.add("Traffic_Status"); hits.clear()
try:
    api.fetch_status(r); raise SystemExit("D. nessun errore")
except requests.exceptions.Timeout:
    dal = [h for h in hits if h.startswith("/cgi-bin/DAL")]
    print(f"D. endpoint lento: interrotto dopo {len(dal)} richieste")
    assert len(dal) == 2
SLOW.clear()
assert r.ha_zyxel_lock.acquire(timeout=0); r.ha_zyxel_lock.release()  # il lock è stato rilasciato

# E. lettura precedente ancora in corso: rinuncia invece di accodarsi
api.LOCK_TIMEOUT = 0.3
held = threading.Event(); done = threading.Event()
threading.Thread(target=lambda: (r.ha_zyxel_lock.acquire(), held.set(), done.wait(), r.ha_zyxel_lock.release())).start()
held.wait(); t = time.time()
try:
    api.fetch_status(r); raise SystemExit("E. nessun errore")
except api.ZyxelBusyError:
    print(f"E. lock occupato: rinuncia dopo {time.time()-t:.1f} s")
done.set()

# G. anche costruttore e login passano dalla stessa connessione
api.REQUEST_TIMEOUT = (10, 30); api.LOCK_TIMEOUT = 45
conns.clear()
r = api.create_router(url, "admin", "pw"); api.fetch_status(r)
print(f"G. avvio + accesso + lettura: {len(conns)} connessioni (l'accesso parte su una nuova)")
assert len(conns) == 2

# H. connessione chiusa dal router tra due letture: la lettura si ripete una volta
real_get = r.ha_zyxel_session.get; calls = []
def flaky(*a, **k):
    calls.append(1)
    if len(calls) == 1: raise requests.exceptions.ConnectionError("RemoteDisconnected")
    return real_get(*a, **k)
r.ha_zyxel_session.get = flaky
data = api.fetch_status(r); r.ha_zyxel_session.get = real_get
assert "cellular" in data and r.sessionkey == "k1"
print("H. connessione caduta: domanda ripetuta, dati completi, accesso conservato")

# I. tempo massimo dell'intera lettura: router lento ma sotto il limite di ogni domanda
api.POLL_BUDGET = 2; SLOW.update(e for e, _ in api._ENDPOINTS); hits.clear(); t = time.time()
try:
    api.fetch_status(r); raise SystemExit("I. nessun errore")
except requests.exceptions.Timeout:
    print(f"I. router lento: lettura chiusa dopo {time.time()-t:.1f} s (senza tetto: ~8 s)")
    assert time.time() - t < 3.5 and r.sessionkey == "k1"
SLOW.clear(); api.POLL_BUDGET = 55

# J. le scritture partono su una connessione nuova
conns.clear(); api.put_object(r, "wlan", {"Index": 1, "wlEnable": True})
print(f"J. scrittura: {len(conns)} connessione nuova")
assert len(conns) == 1

# K. router che manda la risposta a pezzetti: la lettura si chiude comunque al tetto
api.POLL_BUDGET = 3; TRICKLE.add("cellwan_status"); t = time.time()
try:
    api.fetch_status(r); raise SystemExit("K. nessun errore")
except requests.exceptions.Timeout:
    print(f"K. risposta a pezzetti: lettura chiusa dopo {time.time()-t:.1f} s (senza tetto: ~20 s)")
    assert time.time() - t < 4.5
TRICKLE.clear(); api.POLL_BUDGET = 55

# L. creazione del router mentre un'altra operazione tiene il router: rinuncia
api.LOCK_TIMEOUT = 0.3; held.clear(); done.clear()
threading.Thread(target=lambda: (r.ha_zyxel_lock.acquire(), held.set(), done.wait(), r.ha_zyxel_lock.release())).start()
held.wait()
try:
    api.create_router(url, "admin", "pw"); raise SystemExit("L. nessun errore")
except api.ZyxelBusyError:
    print("L. creazione con router occupato: rinuncia")
# M. chiusura di un router mai entrato: non aspetta il lock occupato
r2 = type("R", (), {})(); r2.sessionkey = None; r2.ha_zyxel_session = requests.Session(); r2.ha_zyxel_lock = r.ha_zyxel_lock
t = time.time(); api.close_router(r2)
assert time.time() - t < 0.2
print("M. chiusura senza accesso: immediata")
done.set()

# N. dopo la chiusura una lettura ancora in corso non può rientrare
api.LOCK_TIMEOUT = 45
r3 = api.create_router(url, "admin", "pw"); r3.sessionkey = None
api.close_router(r3)
try:
    api.fetch_status(r3); raise SystemExit("N. nessun errore")
except api.ZyxelConnectionError:
    print("N. router chiuso: nessun nuovo accesso")
# O. avvio con router muto: le due domande iniziali hanno il limite corto
api.SETUP_TIMEOUT = (1, 1); t = time.time()
try:
    api.create_router(f"http://127.0.0.1:{mute.getsockname()[1]}", "admin", "pw")
except requests.exceptions.Timeout:
    print(f"O. avvio con router muto: rinuncia dopo {time.time()-t:.1f} s")
assert r3.params["timeout"] == api.REQUEST_TIMEOUT

# P. corpo con lunghezza dichiarata mandato un byte alla volta: la lettura si chiude al tetto
api.SETUP_TIMEOUT = (10, 30)
r = api.create_router(url, "admin", "pw"); api.fetch_status(r)
api.POLL_BUDGET = 1.5; DRIP.add("cellwan_status"); t = time.time()
try:
    api.fetch_status(r); raise SystemExit("P. nessun errore")
except requests.exceptions.Timeout:
    print(f"P. corpo a gocce: lettura chiusa dopo {time.time()-t:.1f} s (senza tetto: ~30 s)")
    assert time.time() - t < 3
DRIP.clear(); api.POLL_BUDGET = 55

# Q. header poi silenzio: è un timeout, la lettura si ferma e l'accesso resta
api.REQUEST_TIMEOUT = (10, 1); STALL.add("cellwan_status"); hits.clear()
try:
    api.fetch_status(r); raise SystemExit("Q. nessun errore")
except requests.exceptions.Timeout:
    dal = [h for h in hits if h.startswith("/cgi-bin/DAL")]
    print(f"Q. corpo fermo: trattato come timeout, interrotto dopo {len(dal)} richiesta, accesso conservato")
    assert len(dal) == 1 and r.sessionkey == "k1"
STALL.clear(); api.REQUEST_TIMEOUT = (10, 30)

# R. chiusura mentre un accesso è in corso: l'accesso appena ottenuto viene chiuso
r = api.create_router(url, "admin", "pw"); LOGIN_GATE.clear(); hits.clear(); out = []
def poll():
    try: api.fetch_status(r)
    except Exception as e: out.append(e)
th = threading.Thread(target=poll); th.start()
while "/UserLogin" not in hits: time.sleep(0.05)
api.close_router(r); LOGIN_GATE.set(); th.join(5)
assert r.sessionkey is None and any(h.startswith("/cgi-bin/UserLogout") for h in hits), (r.sessionkey, hits)
assert isinstance(out[0], api.ZyxelConnectionError)
print("R. chiusura durante l'accesso: accesso chiuso subito dopo")

# S. la lettura chiede risposte non compresse; se il modem comprime lo stesso, si legge
assert encodings[-1] == "identity" or "identity" in [e for e in encodings if e]
r = api.create_router(url, "admin", "pw"); GZIP.add("status")
data = api.fetch_status(r); GZIP.clear()
assert data["device"]["oid"] == "status"
print("S. risposta compressa comunque: letta correttamente")
# T. uscita con risposta a gocce: la chiusura non resta appesa
LOGOUT_DRIP.append(1); t = time.time(); api.close_router(r); LOGOUT_DRIP.clear()
assert time.time() - t < 2 and r.sessionkey is None
print(f"T. uscita con risposta a gocce: chiusura in {time.time()-t:.1f} s")
print("TUTTO OK")
