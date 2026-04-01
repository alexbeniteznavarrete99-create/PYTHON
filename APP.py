"""
SecureTool - Toolkit de Ciberseguridad
Requiere Python 3.8+ con tkinter (incluido por defecto)
Instala dependencias opcionales: pip install pyperclip
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib
import re
import math
import random
import string
import socket
import ipaddress
import struct
from datetime import datetime


# ──────────────────────────────────────────────
#  PALETA DE COLORES
# ──────────────────────────────────────────────
DARK   = "#0d1117"
PANEL  = "#161b22"
CARD   = "#21262d"
BORDER = "#30363d"
TEXT1  = "#e6edf3"
TEXT2  = "#7d8590"
ACCENT = "#00e5a0"
BLUE   = "#58a6ff"
WARN   = "#ffa940"
DANGER = "#ff4d6d"
OK     = "#52c41a"
MONO   = ("Consolas", 11) if __import__("sys").platform == "win32" else ("Courier New", 11)
MONO_L = ("Consolas", 13) if __import__("sys").platform == "win32" else ("Courier New", 13)

# ──────────────────────────────────────────────
#  LÓGICA DE SEGURIDAD
# ──────────────────────────────────────────────

COMMON_PWORDS = {
    "123456","password","123456789","12345","1234","qwerty","abc123",
    "letmein","monkey","master","dragon","iloveyou","admin","welcome",
    "login","pass","test","111111","000000","123123",
}

COMMON_SEQS = ["123456","abcdef","qwerty","azerty","password","abc123","letmein"]

PORTS_INFO = {
    21:  ("FTP",       "alto",   "Transferencia de archivos sin cifrado. Las credenciales viajan en texto plano."),
    22:  ("SSH",       "bajo",   "Acceso remoto seguro. Usa claves RSA y deshabilita login con contraseña."),
    23:  ("Telnet",    "alto",   "Protocolo obsoleto y sin cifrado. Jamás usar en producción."),
    25:  ("SMTP",      "medio",  "Envío de correo. Sin autenticación puede usarse para spam."),
    53:  ("DNS",       "medio",  "Resolución de nombres. Vulnerable a DNS poisoning y amplification."),
    80:  ("HTTP",      "medio",  "Tráfico web sin cifrar. Cualquier dato puede ser interceptado."),
    110: ("POP3",      "medio",  "Recepción de correo sin cifrado. Usar POP3S (puerto 995)."),
    143: ("IMAP",      "medio",  "Acceso a correo sin cifrado. Preferir IMAPS (puerto 993)."),
    443: ("HTTPS",     "bajo",   "Web cifrada con TLS. Verifica que el certificado esté vigente."),
    445: ("SMB",       "alto",   "Compartición de archivos Windows. Blanco de ransomware (EternalBlue)."),
    1433:("MSSQL",     "alto",   "Base de datos Microsoft SQL Server. Nunca exponer a internet."),
    3306:("MySQL",     "alto",   "Base de datos MySQL/MariaDB. Acceso debe ser solo local."),
    3389:("RDP",       "alto",   "Escritorio remoto Windows. Frecuentemente atacado por ransomware."),
    5432:("PostgreSQL","alto",   "Base de datos PostgreSQL. Nunca exponer directamente a internet."),
    6379:("Redis",     "alto",   "Base de datos en memoria. Por defecto sin autenticación."),
    8080:("HTTP-Alt",  "medio",  "Puerto alternativo HTTP. Usado en proxies y servidores de desarrollo."),
    8443:("HTTPS-Alt", "bajo",   "Puerto alternativo HTTPS. Mismo nivel de seguridad que 443."),
    27017:("MongoDB",  "alto",   "Base de datos NoSQL. Históricamente expuesto sin autenticación."),
}

def analyze_password(pw: str) -> dict:
    has_upper  = bool(re.search(r"[A-Z]", pw))
    has_lower  = bool(re.search(r"[a-z]", pw))
    has_digit  = bool(re.search(r"\d", pw))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", pw))
    has_repeat = bool(re.search(r"(.)\1{2,}", pw))
    has_seq    = any(s in pw.lower() for s in COMMON_SEQS)
    in_common  = pw.lower() in COMMON_PWORDS
    long_enough = len(pw) >= 12

    pool = 0
    if has_upper:  pool += 26
    if has_lower:  pool += 26
    if has_digit:  pool += 10
    if has_symbol: pool += 32
    entropy = round(len(pw) * math.log2(pool)) if pool > 0 else 0
    unique  = len(set(pw))
    variety = sum([has_upper, has_lower, has_digit, has_symbol])

    score = 0
    score += min(len(pw) * 4, 40)
    score += entropy * 0.3
    score += variety * 10
    if has_repeat: score -= 15
    if has_seq:    score -= 20
    if in_common:  score -= 40
    score = max(0, min(100, round(score)))

    if   score < 25: label = "MUY DÉBIL"
    elif score < 50: label = "DÉBIL"
    elif score < 70: label = "MODERADA"
    elif score < 88: label = "FUERTE"
    else:            label = "MUY FUERTE"

    crack = estimate_crack(entropy)

    return {
        "score": score, "label": label, "entropy": entropy,
        "length": len(pw), "unique": unique, "variety": variety,
        "has_upper": has_upper, "has_lower": has_lower,
        "has_digit": has_digit, "has_symbol": has_symbol,
        "has_repeat": has_repeat, "has_seq": has_seq,
        "in_common": in_common, "long_enough": long_enough,
        "crack_time": crack,
    }

def estimate_crack(entropy: int) -> str:
    combos = 2 ** entropy
    hashes_per_sec = 1e10
    secs = combos / hashes_per_sec
    if secs < 1:           return "instantáneo"
    if secs < 60:          return f"{round(secs)} segundos"
    if secs < 3600:        return f"{round(secs/60)} minutos"
    if secs < 86400:       return f"{round(secs/3600)} horas"
    if secs < 31536000:    return f"{round(secs/86400)} días"
    if secs < 31536000000: return f"{round(secs/31536000)} años"
    return "> 1,000 años"

def hash_text(text: str, algorithm: str) -> str:
    algo = algorithm.lower().replace("-", "")
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()

def analyze_url(url: str) -> list:
    results = []
    has_https = url.startswith("https://")
    results.append(("Protocolo seguro", "HTTPS" if has_https else "HTTP (inseguro)", has_https))

    domain = ""
    path   = ""
    try:
        from urllib.parse import urlparse
        p = urlparse(url if "://" in url else "https://" + url)
        domain = p.hostname or ""
        path   = p.path + ("?" + p.query if p.query else "")
    except Exception:
        pass

    is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain))
    results.append(("Tipo de host", f"IP directa (sospechoso)" if is_ip else domain or "no determinado", not is_ip and bool(domain)))

    suspicious_kw = ["login","paypal","verify","secure","account","update","bank","ebay","amazon","apple","google","microsoft"]
    found_kw = [k for k in suspicious_kw if k in url.lower() and (not domain or k not in domain.lower())]
    results.append(("Palabras clave phishing", ", ".join(found_kw) if found_kw else "ninguna detectada", len(found_kw) == 0))

    xss_pattern = bool(re.search(r"<|script|javascript:|onerror|onload", url, re.I))
    results.append(("Parámetros XSS", "posible XSS detectado" if xss_pattern else "sin anomalías", not xss_pattern))

    tld = domain.split(".")[-1].lower() if domain else ""
    bad_tld = tld in ["tk","ml","ga","cf","gq","xyz","top","click","work"]
    results.append(("TLD del dominio", f".{tld}" if tld else "—", not bad_tld))

    url_len = len(url)
    results.append(("Longitud URL", f"{url_len} caracteres" + (" (excesiva)" if url_len > 100 else ""), url_len <= 100))

    has_redirect = bool(re.search(r"redirect=|url=|goto=|return=", url, re.I))
    results.append(("Redireccionamiento abierto", "detectado" if has_redirect else "no detectado", not has_redirect))

    ok_count = sum(1 for r in results if r[2])
    risk = "ALTO" if ok_count < 4 else "MEDIO" if ok_count < 6 else "BAJO"
    return results, risk

def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True) -> str:
    chars = ""
    if upper:   chars += string.ascii_uppercase
    if lower:   chars += string.ascii_lowercase
    if digits:  chars += string.digits
    if symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not chars:
        return "selecciona al menos un tipo"
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))

def calc_subnet(cidr_str: str) -> dict:
    net = ipaddress.IPv4Network(cidr_str, strict=False)
    return {
        "network":   str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "mask":      str(net.netmask),
        "prefix":    net.prefixlen,
        "hosts":     net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses,
        "first":     str(net.network_address + 1) if net.prefixlen < 31 else str(net.network_address),
        "last":      str(net.broadcast_address - 1) if net.prefixlen < 31 else str(net.broadcast_address),
    }

def check_port_open(host: str, port: int, timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ──────────────────────────────────────────────
#  WIDGETS PERSONALIZADOS
# ──────────────────────────────────────────────

def styled_frame(parent, **kw) -> tk.Frame:
    return tk.Frame(parent, bg=PANEL, **kw)

def styled_label(parent, text="", fg=TEXT1, font=None, **kw) -> tk.Label:
    return tk.Label(parent, text=text, fg=fg, bg=parent["bg"],
                    font=font or ("Segoe UI", 10), **kw)

def styled_entry(parent, show="", font=None, **kw) -> tk.Entry:
    e = tk.Entry(parent, bg=CARD, fg=TEXT1, insertbackground=TEXT1,
                 relief="flat", bd=0, font=font or MONO,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=BLUE, show=show, **kw)
    return e

def styled_button(parent, text, command, fg=TEXT1, **kw) -> tk.Button:
    return tk.Button(parent, text=text, command=command,
                     bg=CARD, fg=fg, activebackground=BORDER,
                     activeforeground=TEXT1, relief="flat", bd=0,
                     cursor="hand2", font=("Segoe UI", 10),
                     highlightthickness=1, highlightbackground=BORDER,
                     padx=12, pady=5, **kw)

def copy_to_clipboard(root, text):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


# ──────────────────────────────────────────────
#  PESTAÑA: ANALIZADOR DE CONTRASEÑAS
# ──────────────────────────────────────────────

class PasswordTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self._show = False
        self._build()

    def _build(self):
        # Título
        styled_label(self, "ANALIZADOR DE CONTRASEÑA", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(18,4))

        # Input row
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=20)
        self.pw_var = tk.StringVar()
        self.pw_var.trace_add("write", lambda *_: self._analyze())
        self.entry = styled_entry(row, show="●", textvariable=self.pw_var)
        self.entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.toggle_btn = styled_button(row, "mostrar", self._toggle_show, fg=TEXT2)
        self.toggle_btn.pack(side="left", padx=(6,0))

        # Barra de fortaleza
        bar_bg = tk.Frame(self, bg=BORDER, height=4)
        bar_bg.pack(fill="x", padx=20, pady=(10,0))
        bar_bg.pack_propagate(False)
        self.bar = tk.Frame(bar_bg, bg=PANEL, height=4, width=0)
        self.bar.place(x=0, y=0, relheight=1, relwidth=0)

        # Labels score
        row2 = tk.Frame(self, bg=PANEL)
        row2.pack(fill="x", padx=20, pady=(4,0))
        self.lbl_label = styled_label(row2, "esperando entrada...", fg=TEXT2,
                                      font=("Segoe UI", 9))
        self.lbl_label.pack(side="left")
        self.lbl_score = styled_label(row2, "", fg=TEXT1,
                                      font=("Segoe UI", 10, "bold"))
        self.lbl_score.pack(side="right")

        # Métricas
        mg = tk.Frame(self, bg=PANEL)
        mg.pack(fill="x", padx=20, pady=(14,0))
        for i in range(4):
            mg.columnconfigure(i, weight=1, uniform="m")
        names = ["LONGITUD", "ENTROPÍA (bits)", "ÚNICOS", "VARIEDAD"]
        self.metric_vals = []
        for i, name in enumerate(names):
            card = tk.Frame(mg, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
            card.grid(row=0, column=i, sticky="nsew", padx=(0,6) if i<3 else 0, pady=0)
            styled_label(card, name, fg=TEXT2, font=("Segoe UI", 8)).pack(anchor="w", padx=10, pady=(8,0))
            v = styled_label(card, "—", fg=TEXT1, font=("Segoe UI", 18, "bold"))
            v.pack(anchor="w", padx=10, pady=(2,8))
            self.metric_vals.append(v)

        # Checks
        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", padx=20, pady=12)
        checks_frame = tk.Frame(self, bg=PANEL)
        checks_frame.pack(fill="x", padx=20)
        self.check_labels = {}
        checks = [
            ("long_enough", "Mínimo 12 caracteres"),
            ("has_upper",   "Contiene mayúsculas (A–Z)"),
            ("has_lower",   "Contiene minúsculas (a–z)"),
            ("has_digit",   "Contiene números (0–9)"),
            ("has_symbol",  "Contiene símbolos especiales"),
            ("no_repeat",   "Sin repeticiones excesivas"),
            ("no_seq",      "Sin secuencias comunes"),
            ("not_common",  "No es contraseña común"),
        ]
        for key, text in checks:
            row = tk.Frame(checks_frame, bg=PANEL)
            row.pack(fill="x", pady=2)
            dot = tk.Canvas(row, width=10, height=10, bg=PANEL,
                            highlightthickness=0)
            dot.pack(side="left", padx=(0,8))
            dot.create_oval(1,1,9,9, fill=BORDER, outline="")
            lbl = styled_label(row, text, fg=TEXT2, font=("Segoe UI", 10))
            lbl.pack(side="left")
            self.check_labels[key] = (dot, lbl)

        # Crack time
        sep2 = tk.Frame(self, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=20, pady=12)
        crack_row = tk.Frame(self, bg=CARD, highlightthickness=1,
                             highlightbackground=BORDER)
        crack_row.pack(fill="x", padx=20)
        styled_label(crack_row, "⏱  Tiempo estimado de crackeo (fuerza bruta @ 10B hash/s):",
                     fg=TEXT2, font=("Segoe UI", 9)).pack(side="left", padx=12, pady=8)
        self.lbl_crack = styled_label(crack_row, "—", fg=TEXT1,
                                      font=("Segoe UI", 10, "bold"))
        self.lbl_crack.pack(side="left")

        # Copiar
        btn_row = tk.Frame(self, bg=PANEL)
        btn_row.pack(fill="x", padx=20, pady=12)
        styled_button(btn_row, "limpiar", lambda: self.pw_var.set("")).pack(side="left")

    def _toggle_show(self):
        self._show = not self._show
        self.entry.config(show="" if self._show else "●")
        self.toggle_btn.config(text="ocultar" if self._show else "mostrar")

    def _set_check(self, key, ok):
        dot, lbl = self.check_labels[key]
        color = OK if ok else BORDER
        dot.itemconfig(1, fill=color)
        lbl.config(fg=TEXT1 if ok else TEXT2)

    def _analyze(self):
        pw = self.pw_var.get()
        if not pw:
            self._reset()
            return
        r = analyze_password(pw)
        # Barra
        pct = r["score"] / 100
        color = DANGER if r["score"]<30 else WARN if r["score"]<60 else OK if r["score"]<85 else ACCENT
        self.bar.place(relwidth=pct)
        self.bar.config(bg=color)
        self.lbl_label.config(text=r["label"], fg=color)
        self.lbl_score.config(text=f"{r['score']}/100")
        # Métricas
        self.metric_vals[0].config(text=str(r["length"]))
        self.metric_vals[1].config(text=str(r["entropy"]))
        self.metric_vals[2].config(text=str(r["unique"]))
        self.metric_vals[3].config(text=f"{r['variety']}/4")
        # Checks
        self._set_check("long_enough", r["long_enough"])
        self._set_check("has_upper",   r["has_upper"])
        self._set_check("has_lower",   r["has_lower"])
        self._set_check("has_digit",   r["has_digit"])
        self._set_check("has_symbol",  r["has_symbol"])
        self._set_check("no_repeat",   not r["has_repeat"])
        self._set_check("no_seq",      not r["has_seq"])
        self._set_check("not_common",  not r["in_common"])
        self.lbl_crack.config(text=r["crack_time"])

    def _reset(self):
        self.bar.place(relwidth=0)
        self.lbl_label.config(text="esperando entrada...", fg=TEXT2)
        self.lbl_score.config(text="")
        for v in self.metric_vals:
            v.config(text="—")
        for key in self.check_labels:
            self._set_check(key, False)
        self.lbl_crack.config(text="—")

    def set_password(self, pw):
        self.pw_var.set(pw)


# ──────────────────────────────────────────────
#  PESTAÑA: HASH
# ──────────────────────────────────────────────

class HashTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self.algo = tk.StringVar(value="sha256")
        self._build()

    def _build(self):
        styled_label(self, "GENERADOR Y VERIFICADOR DE HASH", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(18,6))

        # Input
        styled_label(self, "Texto de entrada:", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20)
        self.txt_input = scrolledtext.ScrolledText(self, height=5, bg=CARD,
            fg=TEXT1, insertbackground=TEXT1, relief="flat", bd=0,
            font=MONO, highlightthickness=1, highlightbackground=BORDER)
        self.txt_input.pack(fill="x", padx=20, pady=(4,0))
        self.txt_input.bind("<KeyRelease>", lambda _: self._generate())

        # Algoritmos
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=20, pady=(10,0))
        styled_label(row, "Algoritmo:", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(side="left", padx=(0,10))
        for alg, disp in [("md5","MD5"),("sha1","SHA-1"),("sha256","SHA-256"),
                           ("sha512","SHA-512"),("sha3_256","SHA3-256")]:
            rb = tk.Radiobutton(row, text=disp, variable=self.algo, value=alg,
                                bg=PANEL, fg=TEXT2, selectcolor=CARD,
                                activebackground=PANEL, activeforeground=TEXT1,
                                font=("Segoe UI", 10), cursor="hand2",
                                command=self._generate)
            rb.pack(side="left", padx=4)

        # Resultado
        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", padx=20, pady=10)
        styled_label(self, "Hash generado:", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20)
        res_frame = tk.Frame(self, bg=CARD, highlightthickness=1,
                             highlightbackground=BORDER)
        res_frame.pack(fill="x", padx=20, pady=(4,0))
        self.lbl_hash = styled_label(res_frame, "— ingresa texto arriba",
                                     fg=TEXT2, font=MONO,
                                     wraplength=680, justify="left")
        self.lbl_hash.pack(anchor="w", padx=12, pady=10)

        btn_row = tk.Frame(self, bg=PANEL)
        btn_row.pack(fill="x", padx=20, pady=8)
        styled_button(btn_row, "copiar hash", self._copy).pack(side="left")

        # Stats
        self.lbl_stats = styled_label(btn_row, "", fg=TEXT2,
                                      font=("Segoe UI", 9))
        self.lbl_stats.pack(side="left", padx=12)

        # Verificación de integridad
        sep2 = tk.Frame(self, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=20, pady=(8,0))
        styled_label(self, "VERIFICAR INTEGRIDAD", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(10,6))
        styled_label(self, "Pega el hash esperado:", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20)
        self.compare_entry = styled_entry(self)
        self.compare_entry.pack(fill="x", padx=20, pady=(4,0), ipady=6)
        self.compare_entry.bind("<KeyRelease>", lambda _: self._compare())
        self.lbl_compare = styled_label(self, "esperando comparación...",
                                        fg=TEXT2, font=("Segoe UI", 10))
        self.lbl_compare.pack(anchor="w", padx=20, pady=8)

    def _generate(self):
        text = self.txt_input.get("1.0", "end-1c")
        if not text:
            self.lbl_hash.config(text="— ingresa texto arriba", fg=TEXT2)
            self.lbl_stats.config(text="")
            return
        h = hash_text(text, self.algo.get())
        self.lbl_hash.config(text=h, fg=ACCENT)
        self.lbl_stats.config(text=f"{len(h)*4} bits  |  {len(h)} hex chars  |  {len(text)} bytes entrada")
        self._compare()

    def _copy(self):
        h = self.lbl_hash.cget("text")
        if h.startswith("—"): return
        copy_to_clipboard(self.root, h)
        self.lbl_stats.config(text="¡copiado al portapapeles!")
        self.after(2000, self._generate)

    def _compare(self):
        exp = self.compare_entry.get().strip().lower()
        curr = self.lbl_hash.cget("text").strip().lower()
        if not exp:
            self.lbl_compare.config(text="esperando comparación...", fg=TEXT2)
            return
        if curr.startswith("—"):
            self.lbl_compare.config(text="genera un hash primero", fg=TEXT2)
            return
        if exp == curr:
            self.lbl_compare.config(text="✓  HASHES COINCIDEN — integridad verificada", fg=OK)
        else:
            self.lbl_compare.config(text="✗  HASHES NO COINCIDEN — posible alteración", fg=DANGER)


# ──────────────────────────────────────────────
#  PESTAÑA: ANÁLISIS DE URL
# ──────────────────────────────────────────────

class URLTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self._build()

    def _build(self):
        styled_label(self, "ANÁLISIS DE SEGURIDAD DE URL", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(18,6))

        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=20)
        self.url_entry = styled_entry(row)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.url_entry.bind("<Return>", lambda _: self._analyze())
        styled_button(row, "analizar", self._analyze).pack(side="left", padx=(8,0))

        # Risk badge
        self.risk_frame = tk.Frame(self, bg=PANEL)
        self.risk_frame.pack(fill="x", padx=20, pady=(12,0))

        # Results
        self.results_frame = tk.Frame(self, bg=PANEL)
        self.results_frame.pack(fill="x", padx=20, pady=(8,0))

    def _analyze(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        results, risk = analyze_url(url)

        # Limpiar previos
        for w in self.risk_frame.winfo_children():
            w.destroy()
        for w in self.results_frame.winfo_children():
            w.destroy()

        risk_color = DANGER if risk=="ALTO" else WARN if risk=="MEDIO" else OK
        ok_count = sum(1 for r in results if r[2])
        styled_label(self.risk_frame, f"NIVEL DE RIESGO:", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(side="left")
        styled_label(self.risk_frame, f"  {risk}  ", fg=risk_color,
                     font=("Segoe UI", 11, "bold")).pack(side="left", padx=4)
        styled_label(self.risk_frame, f"({ok_count}/{len(results)} checks OK)", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(side="left")

        for name, val, ok in results:
            r = tk.Frame(self.results_frame, bg=CARD,
                         highlightthickness=1, highlightbackground=BORDER)
            r.pack(fill="x", pady=3)
            dot = tk.Canvas(r, width=10, height=10, bg=CARD,
                            highlightthickness=0)
            dot.pack(side="left", padx=(12,8), pady=10)
            dot.create_oval(1,1,9,9, fill=OK if ok else DANGER, outline="")
            styled_label(r, name, fg=TEXT2,
                         font=("Segoe UI", 10), width=22, anchor="w").pack(side="left")
            styled_label(r, val, fg=TEXT1,
                         font=("Segoe UI", 10)).pack(side="left", padx=8)


# ──────────────────────────────────────────────
#  PESTAÑA: GENERADOR DE CONTRASEÑAS
# ──────────────────────────────────────────────

class GeneratorTab(tk.Frame):
    def __init__(self, parent, root, pw_tab):
        super().__init__(parent, bg=PANEL)
        self.root   = root
        self.pw_tab = pw_tab
        self._build()

    def _build(self):
        styled_label(self, "GENERADOR DE CONTRASEÑAS SEGURAS", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(18,10))

        # Longitud
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=20, pady=(0,10))
        styled_label(row, "Longitud:", fg=TEXT2,
                     font=("Segoe UI", 10)).pack(side="left", padx=(0,10))
        self.len_var = tk.IntVar(value=20)
        self.len_label = styled_label(row, "20", fg=TEXT1,
                                      font=("Segoe UI", 11, "bold"), width=3)
        self.len_label.pack(side="right")
        sl = ttk.Scale(row, from_=8, to=64, orient="horizontal",
                       variable=self.len_var,
                       command=lambda v: [self.len_label.config(text=str(int(float(v)))), self._generate()])
        sl.pack(side="left", fill="x", expand=True)

        # Opciones
        opts_frame = tk.Frame(self, bg=PANEL)
        opts_frame.pack(fill="x", padx=20, pady=(0,10))
        opts_frame.columnconfigure((0,1), weight=1)
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.sym_var   = tk.BooleanVar(value=True)
        for i, (var, text) in enumerate([
            (self.upper_var, "Mayúsculas  A–Z"),
            (self.lower_var, "Minúsculas  a–z"),
            (self.digit_var, "Números  0–9"),
            (self.sym_var,   "Símbolos  !@#$"),
        ]):
            card = tk.Frame(opts_frame, bg=CARD, highlightthickness=1,
                            highlightbackground=BORDER)
            card.grid(row=i//2, column=i%2, sticky="ew",
                      padx=(0,6) if i%2==0 else 0, pady=3)
            cb = tk.Checkbutton(card, text=text, variable=var, bg=CARD,
                                fg=TEXT1, selectcolor=PANEL,
                                activebackground=CARD, activeforeground=TEXT1,
                                font=("Segoe UI", 10), cursor="hand2",
                                command=self._generate)
            cb.pack(anchor="w", padx=10, pady=8)

        # Resultado
        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", padx=20, pady=(8,10))
        styled_label(self, "Contraseña generada:", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20)
        res_frame = tk.Frame(self, bg=CARD, highlightthickness=1,
                             highlightbackground=BORDER)
        res_frame.pack(fill="x", padx=20, pady=(4,0))
        self.lbl_pw = styled_label(res_frame, "—", fg=ACCENT,
                                   font=MONO_L, wraplength=700, justify="left")
        self.lbl_pw.pack(anchor="w", padx=14, pady=12)

        btn_row = tk.Frame(self, bg=PANEL)
        btn_row.pack(fill="x", padx=20, pady=10)
        styled_button(btn_row, "regenerar", self._generate).pack(side="left", padx=(0,6))
        styled_button(btn_row, "copiar", self._copy).pack(side="left", padx=(0,6))
        styled_button(btn_row, "analizar →", self._send_to_analyzer, fg=BLUE).pack(side="left")
        self.lbl_ent = styled_label(btn_row, "", fg=TEXT2, font=("Segoe UI", 9))
        self.lbl_ent.pack(side="right", padx=10)

        self._generate()

    def _generate(self):
        length = int(self.len_var.get())
        self.len_label.config(text=str(length))
        pw = generate_password(
            length=length,
            upper=self.upper_var.get(),
            lower=self.lower_var.get(),
            digits=self.digit_var.get(),
            symbols=self.sym_var.get(),
        )
        self.lbl_pw.config(text=pw)
        # Entropía
        pool = ((26 if self.upper_var.get() else 0) +
                (26 if self.lower_var.get() else 0) +
                (10 if self.digit_var.get() else 0) +
                (30 if self.sym_var.get() else 0))
        if pool > 0:
            ent = round(length * math.log2(pool))
            strength = ("débil" if ent<40 else "moderada" if ent<70
                        else "fuerte" if ent<100 else "muy fuerte")
            self.lbl_ent.config(text=f"entropía: {ent} bits — {strength}")

    def _copy(self):
        pw = self.lbl_pw.cget("text")
        if pw != "—":
            copy_to_clipboard(self.root, pw)

    def _send_to_analyzer(self):
        pw = self.lbl_pw.cget("text")
        if pw and pw != "—":
            self.pw_tab.set_password(pw)
            # Cambiar a pestaña de contraseñas
            self.nametowidget(self.winfo_parent()).select(0)


# ──────────────────────────────────────────────
#  PESTAÑA: RED Y PUERTOS
# ──────────────────────────────────────────────

class NetworkTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self._build()
        self._load_info()

    def _build(self):
        styled_label(self, "INFORMACIÓN DE RED Y PUERTOS", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(18,8))

        # Info cards
        info_grid = tk.Frame(self, bg=PANEL)
        info_grid.pack(fill="x", padx=20, pady=(0,10))
        info_grid.columnconfigure((0,1,2), weight=1)
        self.info_vals = {}
        for i, (key, label) in enumerate([
            ("hostname","HOSTNAME"),("local_ip","IP LOCAL"),("os","PLATAFORMA"),
        ]):
            card = tk.Frame(info_grid, bg=CARD, highlightthickness=1,
                            highlightbackground=BORDER)
            card.grid(row=0, column=i, sticky="nsew",
                      padx=(0,6) if i<2 else 0, pady=0)
            styled_label(card, label, fg=TEXT2, font=("Segoe UI", 8)).pack(
                anchor="w", padx=10, pady=(8,0))
            v = styled_label(card, "...", fg=TEXT1, font=("Segoe UI", 10, "bold"))
            v.pack(anchor="w", padx=10, pady=(2,8))
            self.info_vals[key] = v

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", padx=20, pady=(0,10))

        # Puertos
        styled_label(self, "REFERENCIA DE PUERTOS COMUNES", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20)
        ports_frame = tk.Frame(self, bg=PANEL)
        ports_frame.pack(fill="x", padx=20, pady=(6,0))
        for i, (port, (name, risk, _)) in enumerate(PORTS_INFO.items()):
            risk_color = DANGER if risk=="alto" else WARN if risk=="medio" else OK
            btn = tk.Button(ports_frame,
                            text=f":{port} {name}",
                            bg=CARD, fg=risk_color,
                            activebackground=BORDER, activeforeground=risk_color,
                            relief="flat", bd=0, cursor="hand2",
                            font=("Segoe UI", 9),
                            highlightthickness=1, highlightbackground=BORDER,
                            padx=8, pady=4,
                            command=lambda p=port: self._show_port(p))
            btn.grid(row=i//6, column=i%6, padx=3, pady=3, sticky="ew")
        for c in range(6):
            ports_frame.columnconfigure(c, weight=1)

        self.port_info_frame = tk.Frame(self, bg=CARD, highlightthickness=1,
                                        highlightbackground=BORDER)
        self.port_info_frame.pack(fill="x", padx=20, pady=(10,0))
        self.lbl_port_info = styled_label(self.port_info_frame,
                                          "haz clic en un puerto para ver detalles",
                                          fg=TEXT2, font=("Segoe UI", 10),
                                          wraplength=680, justify="left")
        self.lbl_port_info.pack(anchor="w", padx=14, pady=10)

        sep2 = tk.Frame(self, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=20, pady=(12,0))

        # Subnet calc
        styled_label(self, "CALCULADORA DE SUBNET IPv4", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(10,6))
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=20)
        self.subnet_entry = styled_entry(row)
        self.subnet_entry.insert(0, "192.168.1.0/24")
        self.subnet_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.subnet_entry.bind("<Return>", lambda _: self._calc_subnet())
        styled_button(row, "calcular", self._calc_subnet).pack(side="left", padx=(8,0))

        sub_frame = tk.Frame(self, bg=CARD, highlightthickness=1,
                             highlightbackground=BORDER)
        sub_frame.pack(fill="x", padx=20, pady=(8,0))
        self.lbl_subnet = styled_label(sub_frame, "ingresa una IP con CIDR (ej: 192.168.1.0/24)",
                                       fg=TEXT2, font=MONO,
                                       wraplength=680, justify="left")
        self.lbl_subnet.pack(anchor="w", padx=14, pady=10)

        sep3 = tk.Frame(self, bg=BORDER, height=1)
        sep3.pack(fill="x", padx=20, pady=(12,0))

        # Port scanner
        styled_label(self, "ESCÁNER DE PUERTOS (local)", fg=TEXT2,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(10,6))
        scan_row = tk.Frame(self, bg=PANEL)
        scan_row.pack(fill="x", padx=20)
        styled_label(scan_row, "Host:", fg=TEXT2,
                     font=("Segoe UI", 10)).pack(side="left", padx=(0,6))
        self.scan_host = styled_entry(scan_row, width=20)
        self.scan_host.insert(0, "127.0.0.1")
        self.scan_host.pack(side="left", ipady=5)
        styled_label(scan_row, "  Puertos:", fg=TEXT2,
                     font=("Segoe UI", 10)).pack(side="left", padx=(10,6))
        self.scan_ports = styled_entry(scan_row, width=20)
        self.scan_ports.insert(0, "22,80,443,3306,8080")
        self.scan_ports.pack(side="left", ipady=5)
        styled_button(scan_row, "escanear", self._scan_ports).pack(side="left", padx=(8,0))
        self.scan_result = scrolledtext.ScrolledText(self, height=4, bg=CARD,
            fg=TEXT1, insertbackground=TEXT1, relief="flat", bd=0,
            font=MONO, highlightthickness=1, highlightbackground=BORDER,
            state="disabled")
        self.scan_result.pack(fill="x", padx=20, pady=(8,12))

    def _load_info(self):
        import platform
        try:
            hn = socket.gethostname()
            ip = socket.gethostbyname(hn)
        except:
            hn, ip = "desconocido", "—"
        self.info_vals["hostname"].config(text=hn)
        self.info_vals["local_ip"].config(text=ip)
        self.info_vals["os"].config(text=platform.system() + " " + platform.release())

    def _show_port(self, port):
        name, risk, desc = PORTS_INFO[port]
        risk_color = DANGER if risk=="alto" else WARN if risk=="medio" else OK
        self.lbl_port_info.config(
            text=f"Puerto {port} ({name})  —  RIESGO {risk.upper()}\n\n{desc}",
            fg=TEXT1)

    def _calc_subnet(self):
        try:
            r = calc_subnet(self.subnet_entry.get().strip())
            text = (f"Red:        {r['network']}/{r['prefix']}\n"
                    f"Máscara:    {r['mask']}\n"
                    f"Broadcast:  {r['broadcast']}\n"
                    f"Rango:      {r['first']}  →  {r['last']}\n"
                    f"Hosts:      {r['hosts']:,}")
            self.lbl_subnet.config(text=text, fg=ACCENT)
        except Exception as e:
            self.lbl_subnet.config(text=f"Error: {e}", fg=DANGER)

    def _scan_ports(self):
        host = self.scan_host.get().strip()
        raw  = self.scan_ports.get().strip()
        try:
            ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
        except:
            return
        self.scan_result.config(state="normal")
        self.scan_result.delete("1.0", "end")
        self.scan_result.insert("end", f"Escaneando {host}...\n")
        self.scan_result.config(state="disabled")
        self.update()

        def run():
            lines = []
            for port in ports:
                open_ = check_port_open(host, port, timeout=0.8)
                info = PORTS_INFO.get(port, (str(port),"—",""))
                status = "ABIERTO " if open_ else "cerrado"
                color_hint = "  ⚠" if (open_ and info[1]=="alto") else ""
                lines.append(f"  :{port:<6} {info[0]:<12} {'['+status+']'}{color_hint}")
            self.scan_result.config(state="normal")
            self.scan_result.delete("1.0","end")
            self.scan_result.insert("end", f"Resultado — {host}\n")
            self.scan_result.insert("end", "─"*40 + "\n")
            for l in lines:
                self.scan_result.insert("end", l + "\n")
            self.scan_result.config(state="disabled")

        self.after(50, run)


# ──────────────────────────────────────────────
#  VENTANA PRINCIPAL
# ──────────────────────────────────────────────

class SecureTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureTool — Cybersecurity Toolkit")
        self.geometry("820x720")
        self.minsize(700, 600)
        self.configure(bg=DARK)
        self._build_header()
        self._build_notebook()
        self._style_notebook()
        self.update_idletasks()
        self.center()

    def center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"+{x}+{y}")

    def _build_header(self):
        hdr = tk.Frame(self, bg=PANEL, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Frame(hdr, bg=BORDER, width=3).pack(side="left", fill="y", padx=(18,0))
        inner = tk.Frame(hdr, bg=PANEL)
        inner.pack(side="left", padx=14)
        tk.Label(inner, text="SECURETOOL", fg=ACCENT, bg=PANEL,
                 font=("Consolas", 14, "bold")).pack(anchor="w")
        tk.Label(inner, text="CYBERSECURITY TOOLKIT  v2.0", fg=TEXT2, bg=PANEL,
                 font=("Segoe UI", 8)).pack(anchor="w")
        ts = tk.Label(hdr, text=datetime.now().strftime("%Y-%m-%d  %H:%M"),
                      fg=TEXT2, bg=PANEL, font=("Consolas", 9))
        ts.pack(side="right", padx=18)

    def _style_notebook(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Dark.TNotebook", background=DARK, borderwidth=0,
                        tabmargins=[0,0,0,0])
        style.configure("Dark.TNotebook.Tab", background=PANEL,
                        foreground=TEXT2, padding=[16, 8],
                        font=("Segoe UI", 10), borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", TEXT1)])

    def _build_notebook(self):
        self.nb = ttk.Notebook(self, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True, padx=0, pady=0)

        pw_tab   = PasswordTab(self.nb, self)
        hash_tab = HashTab(self.nb, self)
        url_tab  = URLTab(self.nb, self)
        gen_tab  = GeneratorTab(self.nb, self, pw_tab)
        net_tab  = NetworkTab(self.nb, self)

        for tab, name in [(pw_tab,"  Contraseñas  "),
                          (hash_tab,"  Hash  "),
                          (url_tab,"  URL  "),
                          (gen_tab,"  Generador  "),
                          (net_tab,"  Red / Puertos  ")]:
            # Scroll
            canvas = tk.Canvas(self.nb, bg=PANEL, highlightthickness=0,
                               borderwidth=0)
            vsb = ttk.Scrollbar(self.nb, orient="vertical",
                                command=canvas.yview)
            tab.pack(fill="x")
            canvas.create_window(0, 0, anchor="nw", window=tab)
            canvas.configure(yscrollcommand=vsb.set)
            tab.bind("<Configure>",
                     lambda e, c=canvas: c.configure(
                         scrollregion=c.bbox("all"),
                         width=e.width))
            canvas.bind("<MouseWheel>",
                        lambda e, c=canvas: c.yview_scroll(
                            int(-1*(e.delta/120)), "units"))
            frame = tk.Frame(self.nb, bg=PANEL)
            canvas.pack(in_=frame, side="left", fill="both", expand=True)
            vsb.pack(in_=frame, side="right", fill="y")
            self.nb.add(frame, text=name)


if __name__ == "__main__":
    app = SecureTool()
    app.mainloop()