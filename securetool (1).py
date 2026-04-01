"""
SecureTool - Toolkit de Ciberseguridad
Requiere Python 3.8+ con tkinter (incluido por defecto)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import hashlib
import re
import math
import random
import string
import socket
import ipaddress
import platform
import sys
from datetime import datetime

# ──────────────────────────────────────────────
#  COLORES
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
OK     = "#3fb950"

if sys.platform == "win32":
    FONT_MONO  = ("Consolas", 10)
    FONT_MONO_L= ("Consolas", 12)
    FONT_UI    = ("Segoe UI", 10)
    FONT_UI_S  = ("Segoe UI", 9)
    FONT_UI_B  = ("Segoe UI", 10, "bold")
    FONT_TITLE = ("Consolas", 13, "bold")
else:
    FONT_MONO  = ("Courier New", 10)
    FONT_MONO_L= ("Courier New", 12)
    FONT_UI    = ("Helvetica", 10)
    FONT_UI_S  = ("Helvetica", 9)
    FONT_UI_B  = ("Helvetica", 10, "bold")
    FONT_TITLE = ("Courier New", 13, "bold")

# ──────────────────────────────────────────────
#  LÓGICA DE SEGURIDAD
# ──────────────────────────────────────────────
COMMON_PWORDS = {
    "123456","password","123456789","12345","1234","qwerty","abc123",
    "letmein","monkey","master","dragon","iloveyou","admin","welcome",
    "login","pass","test","111111","000000","123123",
}
COMMON_SEQS = ["123456","abcdef","qwerty","azerty","password","abc123"]

PORTS_INFO = {
    21:   ("FTP",        "alto",   "Sin cifrado. Credenciales viajan en texto plano."),
    22:   ("SSH",        "bajo",   "Acceso remoto seguro. Usa claves RSA, deshabilita login por contraseña."),
    23:   ("Telnet",     "alto",   "Protocolo obsoleto sin cifrado. Nunca usar en producción."),
    25:   ("SMTP",       "medio",  "Envío de correo. Sin autenticación puede usarse para spam."),
    53:   ("DNS",        "medio",  "Vulnerable a DNS poisoning y ataques de amplification."),
    80:   ("HTTP",       "medio",  "Web sin cifrar. Cualquier dato puede ser interceptado."),
    110:  ("POP3",       "medio",  "Correo sin cifrado. Prefiere POP3S (puerto 995)."),
    143:  ("IMAP",       "medio",  "Correo sin cifrado. Prefiere IMAPS (puerto 993)."),
    443:  ("HTTPS",      "bajo",   "Web cifrada TLS. Verifica que el certificado esté vigente."),
    445:  ("SMB",        "alto",   "Compartición Windows. Blanco frecuente de ransomware (EternalBlue)."),
    1433: ("MSSQL",      "alto",   "SQL Server de Microsoft. Nunca exponer directamente a internet."),
    3306: ("MySQL",      "alto",   "MySQL/MariaDB. El acceso debe ser solo local o por VPN."),
    3389: ("RDP",        "alto",   "Escritorio remoto Windows. Blanco frecuente de ransomware."),
    5432: ("PostgreSQL", "alto",   "PostgreSQL. Nunca exponer directamente a internet."),
    6379: ("Redis",      "alto",   "Sin autenticación por defecto. Datos expuestos públicamente."),
    8080: ("HTTP-Alt",   "medio",  "Puerto alternativo HTTP. Usado en proxies y servidores dev."),
    27017:("MongoDB",    "alto",   "Históricamente expuesto sin autenticación en instancias públicas."),
}

def analyze_password(pw):
    has_upper  = bool(re.search(r"[A-Z]", pw))
    has_lower  = bool(re.search(r"[a-z]", pw))
    has_digit  = bool(re.search(r"\d", pw))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", pw))
    has_repeat = bool(re.search(r"(.)\1{2,}", pw))
    has_seq    = any(s in pw.lower() for s in COMMON_SEQS)
    in_common  = pw.lower() in COMMON_PWORDS
    pool = ((26 if has_upper else 0) + (26 if has_lower else 0) +
            (10 if has_digit else 0) + (32 if has_symbol else 0))
    entropy = round(len(pw) * math.log2(pool)) if pool > 0 else 0
    variety = sum([has_upper, has_lower, has_digit, has_symbol])
    score = min(len(pw) * 4, 40) + entropy * 0.3 + variety * 10
    if has_repeat: score -= 15
    if has_seq:    score -= 20
    if in_common:  score -= 40
    score = max(0, min(100, round(score)))
    label = ("MUY DÉBIL" if score < 25 else "DÉBIL" if score < 50 else
             "MODERADA" if score < 70 else "FUERTE" if score < 88 else "MUY FUERTE")
    secs = (2 ** entropy) / 1e10
    if secs < 1:          crack = "instantáneo"
    elif secs < 60:       crack = f"{round(secs)} segundos"
    elif secs < 3600:     crack = f"{round(secs/60)} minutos"
    elif secs < 86400:    crack = f"{round(secs/3600)} horas"
    elif secs < 31536000: crack = f"{round(secs/86400)} días"
    elif secs < 3.15e10:  crack = f"{round(secs/31536000)} años"
    else:                 crack = "> 1,000 años"
    return dict(score=score, label=label, entropy=entropy, length=len(pw),
                unique=len(set(pw)), variety=variety, has_upper=has_upper,
                has_lower=has_lower, has_digit=has_digit, has_symbol=has_symbol,
                has_repeat=has_repeat, has_seq=has_seq, in_common=in_common,
                long_enough=len(pw) >= 12, crack_time=crack)

def hash_text(text, algo):
    name = algo.lower().replace("-", "")
    h = hashlib.new(name)
    h.update(text.encode("utf-8"))
    return h.hexdigest()

def analyze_url(url):
    results = []
    has_https = url.startswith("https://")
    results.append(("Protocolo seguro",  "HTTPS ✓" if has_https else "HTTP — inseguro", has_https))
    domain = ""
    try:
        from urllib.parse import urlparse
        p = urlparse(url if "://" in url else "https://" + url)
        domain = p.hostname or ""
    except: pass
    is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain))
    results.append(("Tipo de host", "IP directa (sospechoso)" if is_ip else domain or "—", not is_ip and bool(domain)))
    kws   = ["login","paypal","verify","secure","account","update","bank","ebay","amazon","apple","google","microsoft"]
    found = [k for k in kws if k in url.lower() and (not domain or k not in domain.lower())]
    results.append(("Palabras phishing",  ", ".join(found) if found else "ninguna detectada", not found))
    xss = bool(re.search(r"<|script|javascript:|onerror|onload", url, re.I))
    results.append(("Posible XSS",        "detectado !" if xss else "sin anomalías", not xss))
    tld     = domain.split(".")[-1].lower() if domain else ""
    bad_tld = tld in ["tk","ml","ga","cf","gq","xyz","top","click","work"]
    results.append(("TLD del dominio",    f".{tld}" if tld else "—", not bad_tld))
    results.append(("Longitud URL",       f"{len(url)} chars" + (" (excesiva)" if len(url) > 100 else ""), len(url) <= 100))
    redir = bool(re.search(r"redirect=|url=|goto=|return=", url, re.I))
    results.append(("Redirección abierta","detectada" if redir else "no detectada", not redir))
    ok   = sum(1 for r in results if r[2])
    risk = "ALTO" if ok < 4 else "MEDIO" if ok < 6 else "BAJO"
    return results, risk

def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True):
    chars = ""
    if upper:   chars += string.ascii_uppercase
    if lower:   chars += string.ascii_lowercase
    if digits:  chars += string.digits
    if symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not chars: return "selecciona al menos un tipo"
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))

def calc_subnet(cidr_str):
    net   = ipaddress.IPv4Network(cidr_str, strict=False)
    hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
    return dict(network=str(net.network_address), broadcast=str(net.broadcast_address),
                mask=str(net.netmask), prefix=net.prefixlen, hosts=hosts,
                first=str(net.network_address + (1 if net.prefixlen < 31 else 0)),
                last=str(net.broadcast_address  - (1 if net.prefixlen < 31 else 0)))

def check_port(host, port, timeout=0.8):
    try:
        with socket.create_connection((host, port), timeout=timeout): return True
    except: return False

# ──────────────────────────────────────────────
#  WIDGETS HELPER
# ──────────────────────────────────────────────
def lbl(parent, text="", fg=TEXT1, font=None, **kw):
    return tk.Label(parent, text=text, fg=fg, bg=parent["bg"],
                    font=font or FONT_UI, **kw)

def ent(parent, show="", **kw):
    return tk.Entry(parent, bg=CARD, fg=TEXT1, insertbackground=TEXT1,
                    relief="flat", bd=0, font=FONT_MONO, highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=BLUE, show=show, **kw)

def button(parent, text, cmd, fg=TEXT1, **kw):
    return tk.Button(parent, text=text, command=cmd, bg=CARD, fg=fg,
                     activebackground=BORDER, activeforeground=TEXT1,
                     relief="flat", bd=0, cursor="hand2", font=FONT_UI,
                     highlightthickness=1, highlightbackground=BORDER,
                     padx=10, pady=4, **kw)

def hsep(parent, pady=8):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=pady)

def cframe(parent, **kw):
    return tk.Frame(parent, bg=CARD, highlightthickness=1,
                    highlightbackground=BORDER, **kw)

def copy_clip(root, text):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()

# ──────────────────────────────────────────────
#  SCROLLABLE FRAME (robusto)
# ──────────────────────────────────────────────
class ScrollFrame(tk.Frame):
    """Frame con scroll vertical que funciona correctamente."""
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=DARK, **kw)
        self.canvas = tk.Canvas(self, bg=PANEL, highlightthickness=0, bd=0)
        self.vsb    = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=PANEL)
        self._win  = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_inner)
        self.canvas.bind("<Configure>", self._on_canvas)
        self.canvas.bind("<MouseWheel>", self._scroll)
        self.inner.bind("<MouseWheel>", self._scroll)

    def _on_inner(self, e):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas(self, e):
        self.canvas.itemconfig(self._win, width=e.width)

    def _scroll(self, e):
        self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

    def bind_scroll(self, widget):
        widget.bind("<MouseWheel>", self._scroll)


# ──────────────────────────────────────────────
#  CONTENIDO PESTAÑAS
# ──────────────────────────────────────────────

class PasswordContent(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root  = root
        self._show = False
        self._build()

    def _build(self):
        lbl(self, "ANALIZADOR DE CONTRASEÑA", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(16,4))

        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=16)
        self.pw_var = tk.StringVar()
        self.pw_var.trace_add("write", lambda *_: self._analyze())
        self.pw_ent = ent(row, show="●")
        self.pw_ent.config(textvariable=self.pw_var)
        self.pw_ent.pack(side="left", fill="x", expand=True, ipady=8)
        self.tog = button(row, "mostrar", self._toggle, fg=TEXT2)
        self.tog.pack(side="left", padx=(6, 0))

        # Barra
        bar_bg = tk.Frame(self, bg=BORDER, height=5)
        bar_bg.pack(fill="x", padx=16, pady=(10, 0))
        self.bar = tk.Frame(bar_bg, bg=PANEL, height=5)
        self.bar.place(x=0, y=0, relheight=1, relwidth=0)

        row2 = tk.Frame(self, bg=PANEL)
        row2.pack(fill="x", padx=16, pady=(4, 0))
        self.lbl_st = lbl(row2, "esperando entrada...", fg=TEXT2, font=FONT_UI_S)
        self.lbl_st.pack(side="left")
        self.lbl_sc = lbl(row2, "", fg=TEXT1, font=FONT_UI_B)
        self.lbl_sc.pack(side="right")

        # Métricas
        mg = tk.Frame(self, bg=PANEL)
        mg.pack(fill="x", padx=16, pady=(14, 0))
        self.mv = []
        for i, name in enumerate(["LONGITUD", "ENTROPÍA (bits)", "ÚNICOS", "VARIEDAD"]):
            c = cframe(mg)
            c.grid(row=0, column=i, sticky="nsew", padx=(0, 5) if i < 3 else 0)
            mg.columnconfigure(i, weight=1)
            lbl(c, name, fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=8, pady=(7, 0))
            v = lbl(c, "—", fg=TEXT1, font=FONT_MONO_L)
            v.pack(anchor="w", padx=8, pady=(2, 7))
            self.mv.append(v)

        hsep(self, 12)

        # Checks
        self.chk = {}
        cf = tk.Frame(self, bg=PANEL)
        cf.pack(fill="x", padx=16)
        for key, text in [
            ("long_enough", "Mínimo 12 caracteres"),
            ("has_upper",   "Contiene mayúsculas (A–Z)"),
            ("has_lower",   "Contiene minúsculas (a–z)"),
            ("has_digit",   "Contiene números (0–9)"),
            ("has_symbol",  "Contiene símbolos especiales"),
            ("no_repeat",   "Sin repeticiones excesivas (ej: aaa)"),
            ("no_seq",      "Sin secuencias comunes (ej: qwerty)"),
            ("not_common",  "No es una contraseña conocida"),
        ]:
            r = tk.Frame(cf, bg=PANEL)
            r.pack(fill="x", pady=2)
            dot = tk.Canvas(r, width=10, height=10, bg=PANEL, highlightthickness=0)
            dot.pack(side="left", padx=(0, 8))
            dot.create_oval(2, 2, 9, 9, fill=BORDER, outline="", tags="d")
            lb = lbl(r, text, fg=TEXT2, font=FONT_UI)
            lb.pack(side="left")
            self.chk[key] = (dot, lb)

        hsep(self, 12)

        cc = cframe(self)
        cc.pack(fill="x", padx=16)
        row3 = tk.Frame(cc, bg=CARD)
        row3.pack(fill="x", padx=12, pady=8)
        lbl(row3, "Tiempo de crackeo estimado (fuerza bruta, 10B hash/s):", fg=TEXT2, font=FONT_UI_S).pack(side="left")
        self.lbl_cr = lbl(row3, "—", fg=TEXT1, font=FONT_UI_B)
        self.lbl_cr.pack(side="left", padx=6)

        tk.Frame(self, bg=PANEL, height=16).pack()

    def _toggle(self):
        self._show = not self._show
        self.pw_ent.config(show="" if self._show else "●")
        self.tog.config(text="ocultar" if self._show else "mostrar")

    def _set_chk(self, key, ok):
        dot, lb = self.chk[key]
        dot.itemconfig("d", fill=OK if ok else BORDER)
        lb.config(fg=TEXT1 if ok else TEXT2)

    def _analyze(self):
        pw = self.pw_var.get()
        if not pw: self._reset(); return
        r = analyze_password(pw)
        color = DANGER if r["score"] < 30 else WARN if r["score"] < 60 else OK if r["score"] < 85 else ACCENT
        self.bar.place(relwidth=r["score"] / 100)
        self.bar.config(bg=color)
        self.lbl_st.config(text=r["label"], fg=color)
        self.lbl_sc.config(text=f"{r['score']}/100")
        self.mv[0].config(text=str(r["length"]))
        self.mv[1].config(text=str(r["entropy"]))
        self.mv[2].config(text=str(r["unique"]))
        self.mv[3].config(text=f"{r['variety']}/4")
        self._set_chk("long_enough", r["long_enough"])
        self._set_chk("has_upper",   r["has_upper"])
        self._set_chk("has_lower",   r["has_lower"])
        self._set_chk("has_digit",   r["has_digit"])
        self._set_chk("has_symbol",  r["has_symbol"])
        self._set_chk("no_repeat",   not r["has_repeat"])
        self._set_chk("no_seq",      not r["has_seq"])
        self._set_chk("not_common",  not r["in_common"])
        self.lbl_cr.config(text=r["crack_time"])

    def _reset(self):
        self.bar.place(relwidth=0)
        self.lbl_st.config(text="esperando entrada...", fg=TEXT2)
        self.lbl_sc.config(text="")
        for v in self.mv: v.config(text="—")
        for k in self.chk: self._set_chk(k, False)
        self.lbl_cr.config(text="—")

    def set_password(self, pw):
        self.pw_ent.delete(0, "end")
        self.pw_ent.insert(0, pw)


class HashContent(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self.algo = tk.StringVar(value="sha256")
        self._build()

    def _build(self):
        lbl(self, "GENERADOR Y VERIFICADOR DE HASH", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(16, 4))
        lbl(self, "Texto de entrada:", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16)
        self.txt = scrolledtext.ScrolledText(self, height=5, bg=CARD, fg=TEXT1,
            insertbackground=TEXT1, relief="flat", bd=0, font=FONT_MONO,
            highlightthickness=1, highlightbackground=BORDER)
        self.txt.pack(fill="x", padx=16, pady=(4, 0))
        self.txt.bind("<KeyRelease>", lambda _: self._gen())

        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=16, pady=(8, 0))
        lbl(row, "Algoritmo:", fg=TEXT2, font=FONT_UI_S).pack(side="left", padx=(0, 8))
        for alg, disp in [("md5","MD5"),("sha1","SHA-1"),("sha256","SHA-256"),("sha512","SHA-512"),("sha3_256","SHA3-256")]:
            tk.Radiobutton(row, text=disp, variable=self.algo, value=alg,
                bg=PANEL, fg=TEXT2, selectcolor=CARD, activebackground=PANEL,
                activeforeground=TEXT1, font=FONT_UI, cursor="hand2",
                command=self._gen).pack(side="left", padx=3)

        hsep(self, 8)
        lbl(self, "Hash generado:", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16)
        hc = cframe(self)
        hc.pack(fill="x", padx=16, pady=(4, 0))
        self.lbl_h = lbl(hc, "— ingresa texto arriba", fg=TEXT2, font=FONT_MONO,
                         wraplength=700, justify="left")
        self.lbl_h.pack(anchor="w", padx=12, pady=10)

        brow = tk.Frame(self, bg=PANEL)
        brow.pack(fill="x", padx=16, pady=8)
        button(brow, "copiar hash", self._copy).pack(side="left")
        self.lbl_info = lbl(brow, "", fg=TEXT2, font=FONT_UI_S)
        self.lbl_info.pack(side="left", padx=10)

        hsep(self, 6)
        lbl(self, "VERIFICAR INTEGRIDAD", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(4, 4))
        lbl(self, "Pega el hash esperado para comparar:", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16)
        self.cmp = ent(self)
        self.cmp.pack(fill="x", padx=16, pady=(4, 0), ipady=6)
        self.cmp.bind("<KeyRelease>", lambda _: self._compare())
        self.lbl_cmp = lbl(self, "esperando comparación...", fg=TEXT2, font=FONT_UI)
        self.lbl_cmp.pack(anchor="w", padx=16, pady=8)
        tk.Frame(self, bg=PANEL, height=16).pack()

    def _gen(self):
        text = self.txt.get("1.0", "end-1c")
        if not text:
            self.lbl_h.config(text="— ingresa texto arriba", fg=TEXT2)
            self.lbl_info.config(text=""); return
        h = hash_text(text, self.algo.get())
        self.lbl_h.config(text=h, fg=ACCENT)
        self.lbl_info.config(text=f"{len(h)*4} bits  |  {len(h)} hex chars")
        self._compare()

    def _copy(self):
        h = self.lbl_h.cget("text")
        if h.startswith("—"): return
        copy_clip(self.root, h)
        self.lbl_info.config(text="¡copiado!")
        self.after(1500, self._gen)

    def _compare(self):
        exp  = self.cmp.get().strip().lower()
        curr = self.lbl_h.cget("text").strip().lower()
        if not exp:   self.lbl_cmp.config(text="esperando comparación...", fg=TEXT2); return
        if curr.startswith("—"): self.lbl_cmp.config(text="genera un hash primero", fg=TEXT2); return
        if exp == curr:
            self.lbl_cmp.config(text="✓  HASHES COINCIDEN — integridad verificada", fg=OK)
        else:
            self.lbl_cmp.config(text="✗  HASHES NO COINCIDEN — posible alteración", fg=DANGER)


class URLContent(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self._build()

    def _build(self):
        lbl(self, "ANÁLISIS DE SEGURIDAD DE URL", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(16, 4))
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=16)
        self.url_ent = ent(row)
        self.url_ent.pack(side="left", fill="x", expand=True, ipady=8)
        self.url_ent.bind("<Return>", lambda _: self._analyze())
        button(row, "analizar", self._analyze).pack(side="left", padx=(8, 0))
        self.risk_row = tk.Frame(self, bg=PANEL)
        self.risk_row.pack(fill="x", padx=16, pady=(10, 0))
        self.res_frame = tk.Frame(self, bg=PANEL)
        self.res_frame.pack(fill="x", padx=16, pady=(6, 0))
        tk.Frame(self, bg=PANEL, height=16).pack()

    def _analyze(self):
        url = self.url_ent.get().strip()
        if not url: return
        results, risk = analyze_url(url)
        for w in self.risk_row.winfo_children(): w.destroy()
        for w in self.res_frame.winfo_children(): w.destroy()
        rc = DANGER if risk == "ALTO" else WARN if risk == "MEDIO" else OK
        ok_count = sum(1 for r in results if r[2])
        lbl(self.risk_row, "RIESGO:", fg=TEXT2, font=FONT_UI_S).pack(side="left")
        lbl(self.risk_row, f"  {risk}  ", fg=rc, font=FONT_UI_B).pack(side="left")
        lbl(self.risk_row, f"({ok_count}/{len(results)} checks OK)", fg=TEXT2, font=FONT_UI_S).pack(side="left", padx=4)
        for name, val, ok in results:
            r = cframe(self.res_frame)
            r.pack(fill="x", pady=2)
            inner = tk.Frame(r, bg=CARD)
            inner.pack(fill="x", padx=10, pady=6)
            dot = tk.Canvas(inner, width=10, height=10, bg=CARD, highlightthickness=0)
            dot.pack(side="left", padx=(0, 8))
            dot.create_oval(1, 1, 9, 9, fill=OK if ok else DANGER, outline="")
            lbl(inner, name, fg=TEXT2, font=FONT_UI, width=22, anchor="w").pack(side="left")
            lbl(inner, val,  fg=TEXT1, font=FONT_UI).pack(side="left")


class GeneratorContent(tk.Frame):
    def __init__(self, parent, root, pw_content, notebook):
        super().__init__(parent, bg=PANEL)
        self.root       = root
        self.pw_content = pw_content
        self.notebook   = notebook
        self._build()

    def _build(self):
        lbl(self, "GENERADOR DE CONTRASEÑAS SEGURAS", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(16, 10))

        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=16, pady=(0, 8))
        lbl(row, "Longitud:", fg=TEXT2, font=FONT_UI).pack(side="left", padx=(0, 8))
        self.len_var = tk.IntVar(value=20)
        self.len_lbl = lbl(row, "20", fg=TEXT1, font=FONT_UI_B, width=3)
        self.len_lbl.pack(side="right")
        ttk.Scale(row, from_=8, to=64, orient="horizontal", variable=self.len_var,
                  command=lambda v: [self.len_lbl.config(text=str(int(float(v)))), self._gen()]
                  ).pack(side="left", fill="x", expand=True)

        og = tk.Frame(self, bg=PANEL)
        og.pack(fill="x", padx=16, pady=(0, 8))
        og.columnconfigure((0, 1), weight=1)
        self.upper_v = tk.BooleanVar(value=True)
        self.lower_v = tk.BooleanVar(value=True)
        self.digit_v = tk.BooleanVar(value=True)
        self.sym_v   = tk.BooleanVar(value=True)
        for i, (var, txt) in enumerate([(self.upper_v, "Mayúsculas  A–Z"), (self.lower_v, "Minúsculas  a–z"),
                                         (self.digit_v, "Números  0–9"),    (self.sym_v,   "Símbolos  !@#$")]):
            c = cframe(og)
            c.grid(row=i // 2, column=i % 2, sticky="ew", padx=(0, 5) if i % 2 == 0 else 0, pady=3)
            tk.Checkbutton(c, text=txt, variable=var, bg=CARD, fg=TEXT1,
                selectcolor=PANEL, activebackground=CARD, activeforeground=TEXT1,
                font=FONT_UI, cursor="hand2", command=self._gen).pack(anchor="w", padx=10, pady=6)

        hsep(self, 8)
        lbl(self, "Contraseña generada:", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16)
        gc = cframe(self)
        gc.pack(fill="x", padx=16, pady=(4, 0))
        self.lbl_pw = lbl(gc, "—", fg=ACCENT, font=FONT_MONO_L, wraplength=700, justify="left")
        self.lbl_pw.pack(anchor="w", padx=12, pady=12)

        brow = tk.Frame(self, bg=PANEL)
        brow.pack(fill="x", padx=16, pady=8)
        button(brow, "regenerar", self._gen).pack(side="left", padx=(0, 5))
        button(brow, "copiar", self._copy).pack(side="left", padx=(0, 5))
        button(brow, "→ analizar", self._send, fg=BLUE).pack(side="left")
        self.lbl_ent = lbl(brow, "", fg=TEXT2, font=FONT_UI_S)
        self.lbl_ent.pack(side="right")
        tk.Frame(self, bg=PANEL, height=16).pack()
        self._gen()

    def _gen(self):
        length = int(self.len_var.get())
        self.len_lbl.config(text=str(length))
        pw = generate_password(length, self.upper_v.get(), self.lower_v.get(),
                               self.digit_v.get(), self.sym_v.get())
        self.lbl_pw.config(text=pw)
        pool = ((26 if self.upper_v.get() else 0) + (26 if self.lower_v.get() else 0) +
                (10 if self.digit_v.get() else 0) + (30 if self.sym_v.get() else 0))
        if pool > 0:
            e  = round(length * math.log2(pool))
            st = "débil" if e < 40 else "moderada" if e < 70 else "fuerte" if e < 100 else "muy fuerte"
            self.lbl_ent.config(text=f"entropía: {e} bits — {st}")

    def _copy(self):
        pw = self.lbl_pw.cget("text")
        if pw != "—": copy_clip(self.root, pw)

    def _send(self):
        pw = self.lbl_pw.cget("text")
        if pw and pw != "—":
            self.pw_content.set_password(pw)
            self.notebook.select(0)


class NetworkContent(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=PANEL)
        self.root = root
        self._build()
        self._load_info()

    def _build(self):
        lbl(self, "INFORMACIÓN DE RED Y PUERTOS", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(16, 8))

        ig = tk.Frame(self, bg=PANEL)
        ig.pack(fill="x", padx=16, pady=(0, 8))
        ig.columnconfigure((0, 1, 2), weight=1)
        self.inf = {}
        for i, (k, name) in enumerate([("host", "HOSTNAME"), ("ip", "IP LOCAL"), ("os", "SISTEMA")]):
            c = cframe(ig)
            c.grid(row=0, column=i, sticky="nsew", padx=(0, 5) if i < 2 else 0)
            lbl(c, name, fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=8, pady=(6, 0))
            v = lbl(c, "...", fg=TEXT1, font=FONT_UI_B)
            v.pack(anchor="w", padx=8, pady=(2, 6))
            self.inf[k] = v

        hsep(self, 6)
        lbl(self, "REFERENCIA DE PUERTOS (clic para detalles)", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(4, 6))

        pf = tk.Frame(self, bg=PANEL)
        pf.pack(fill="x", padx=16)
        cols = 5
        for i, (port, (name, risk, _)) in enumerate(PORTS_INFO.items()):
            rc = DANGER if risk == "alto" else WARN if risk == "medio" else OK
            tk.Button(pf, text=f":{port}\n{name}", bg=CARD, fg=rc,
                activebackground=BORDER, activeforeground=rc, relief="flat",
                bd=0, cursor="hand2", font=FONT_UI_S, width=9,
                highlightthickness=1, highlightbackground=BORDER,
                padx=4, pady=4, command=lambda p=port: self._show_port(p)
            ).grid(row=i // cols, column=i % cols, padx=2, pady=2, sticky="ew")
        for c in range(cols): pf.columnconfigure(c, weight=1)

        pc = cframe(self)
        pc.pack(fill="x", padx=16, pady=(8, 0))
        self.lbl_port = lbl(pc, "Selecciona un puerto para ver detalles de seguridad.",
                            fg=TEXT2, font=FONT_UI, wraplength=680, justify="left")
        self.lbl_port.pack(anchor="w", padx=12, pady=10)

        hsep(self, 10)
        lbl(self, "CALCULADORA DE SUBNET IPv4", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(4, 6))
        srow = tk.Frame(self, bg=PANEL)
        srow.pack(fill="x", padx=16)
        self.sub_ent = ent(srow)
        self.sub_ent.insert(0, "192.168.1.0/24")
        self.sub_ent.pack(side="left", fill="x", expand=True, ipady=6)
        self.sub_ent.bind("<Return>", lambda _: self._calc_sub())
        button(srow, "calcular", self._calc_sub).pack(side="left", padx=(8, 0))
        sc = cframe(self)
        sc.pack(fill="x", padx=16, pady=(6, 0))
        self.lbl_sub = lbl(sc, "Ingresa una IP con CIDR (ej: 192.168.1.0/24)",
                           fg=TEXT2, font=FONT_MONO, justify="left")
        self.lbl_sub.pack(anchor="w", padx=12, pady=10)

        hsep(self, 10)
        lbl(self, "ESCÁNER DE PUERTOS TCP", fg=TEXT2, font=FONT_UI_S).pack(anchor="w", padx=16, pady=(4, 6))
        scrow = tk.Frame(self, bg=PANEL)
        scrow.pack(fill="x", padx=16)
        lbl(scrow, "Host:", fg=TEXT2, font=FONT_UI).pack(side="left", padx=(0, 6))
        self.scan_h = ent(scrow, width=18)
        self.scan_h.insert(0, "127.0.0.1")
        self.scan_h.pack(side="left", ipady=5)
        lbl(scrow, "  Puertos:", fg=TEXT2, font=FONT_UI).pack(side="left", padx=(8, 6))
        self.scan_p = ent(scrow, width=24)
        self.scan_p.insert(0, "22,80,443,3306,8080")
        self.scan_p.pack(side="left", ipady=5)
        button(scrow, "escanear", self._scan).pack(side="left", padx=(8, 0))
        self.scan_out = scrolledtext.ScrolledText(self, height=6, bg=CARD, fg=TEXT1,
            insertbackground=TEXT1, relief="flat", bd=0, font=FONT_MONO,
            highlightthickness=1, highlightbackground=BORDER, state="disabled")
        self.scan_out.pack(fill="x", padx=16, pady=(8, 16))

    def _load_info(self):
        try:
            hn = socket.gethostname()
            ip = socket.gethostbyname(hn)
        except:
            hn, ip = "desconocido", "—"
        self.inf["host"].config(text=hn)
        self.inf["ip"].config(text=ip)
        self.inf["os"].config(text=f"{platform.system()} {platform.release()}")

    def _show_port(self, port):
        name, risk, desc = PORTS_INFO[port]
        rc = DANGER if risk == "alto" else WARN if risk == "medio" else OK
        self.lbl_port.config(text=f"Puerto {port} ({name})  —  RIESGO {risk.upper()}\n{desc}", fg=TEXT1)

    def _calc_sub(self):
        try:
            r = calc_subnet(self.sub_ent.get().strip())
            t = (f"Red: {r['network']}/{r['prefix']}    Máscara: {r['mask']}\n"
                 f"Broadcast: {r['broadcast']}    Hosts disponibles: {r['hosts']:,}\n"
                 f"Rango: {r['first']}  →  {r['last']}")
            self.lbl_sub.config(text=t, fg=ACCENT)
        except Exception as e:
            self.lbl_sub.config(text=f"Error: {e}", fg=DANGER)

    def _scan(self):
        host  = self.scan_h.get().strip()
        ports = [int(p.strip()) for p in self.scan_p.get().split(",") if p.strip().isdigit()]
        self.scan_out.config(state="normal")
        self.scan_out.delete("1.0", "end")
        self.scan_out.insert("end", f"Escaneando {host}...\n")
        self.scan_out.config(state="disabled")
        self.update()
        def run():
            lines = [f"Host: {host}   {datetime.now().strftime('%H:%M:%S')}", "─" * 44]
            for port in ports:
                open_ = check_port(host, port)
                name  = PORTS_INFO.get(port, (str(port),))[0]
                risk  = PORTS_INFO.get(port, ("", "—", ""))[1]
                warn  = "  ⚠ riesgo alto" if (open_ and risk == "alto") else ""
                lines.append(f"  :{port:<7} {name:<14} {'[ABIERTO]' if open_ else '[cerrado]'}{warn}")
            self.scan_out.config(state="normal")
            self.scan_out.delete("1.0", "end")
            self.scan_out.insert("end", "\n".join(lines))
            self.scan_out.config(state="disabled")
        self.after(80, run)


# ──────────────────────────────────────────────
#  APP PRINCIPAL
# ──────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureTool — Cybersecurity Toolkit")
        self.geometry("880x720")
        self.minsize(720, 580)
        self.configure(bg=DARK)
        self._style()
        self._header()
        self._tabs()
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - self.winfo_width())  // 2
        y = (self.winfo_screenheight() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("TNotebook", background=DARK, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=TEXT2,
                    padding=[18, 8], font=FONT_UI, borderwidth=0)
        s.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEXT1)])
        s.configure("Vertical.TScrollbar", background=CARD, troughcolor=PANEL,
                    borderwidth=0, arrowcolor=TEXT2, gripcount=0)

    def _header(self):
        h = tk.Frame(self, bg=PANEL, height=54)
        h.pack(fill="x")
        h.pack_propagate(False)
        tk.Frame(h, bg=ACCENT, width=3).pack(side="left", fill="y", padx=(16, 0))
        inner = tk.Frame(h, bg=PANEL)
        inner.pack(side="left", padx=12)
        tk.Label(inner, text="SECURETOOL", fg=ACCENT, bg=PANEL, font=FONT_TITLE).pack(anchor="w")
        tk.Label(inner, text="CYBERSECURITY TOOLKIT  v2.0", fg=TEXT2, bg=PANEL, font=FONT_UI_S).pack(anchor="w")
        tk.Label(h, text=datetime.now().strftime("%Y-%m-%d  %H:%M"),
                 fg=TEXT2, bg=PANEL, font=FONT_MONO).pack(side="right", padx=16)

    def _make_tab(self, nb, ContentClass, *args):
        """Crea un frame con scroll que contiene el contenido de la pestaña."""
        outer = tk.Frame(nb, bg=PANEL)
        canvas = tk.Canvas(outer, bg=PANEL, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        content = ContentClass(canvas, self, *args)
        win_id  = canvas.create_window((0, 0), window=content, anchor="nw")

        def on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(e):
            canvas.itemconfig(win_id, width=e.width)

        def on_scroll(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        content.bind("<Configure>", on_frame_configure)
        canvas.bind("<Configure>", on_canvas_configure)
        canvas.bind("<MouseWheel>", on_scroll)
        # Propagar scroll desde widgets hijos
        def bind_scroll_recursive(widget):
            widget.bind("<MouseWheel>", on_scroll, add="+")
            for child in widget.winfo_children():
                bind_scroll_recursive(child)

        # Bind después de que la ventana sea visible
        def delayed_bind():
            bind_scroll_recursive(content)
        self.after(200, delayed_bind)

        return outer, content

    def _tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        pw_frame,  pw_content  = self._make_tab(nb, PasswordContent)
        nb.add(pw_frame, text="  Contraseñas  ")

        hash_frame, _ = self._make_tab(nb, HashContent)
        nb.add(hash_frame, text="  Hash  ")

        url_frame, _  = self._make_tab(nb, URLContent)
        nb.add(url_frame, text="  URL  ")

        gen_frame, _  = self._make_tab(nb, GeneratorContent, pw_content, nb)
        nb.add(gen_frame, text="  Generador  ")

        net_frame, _  = self._make_tab(nb, NetworkContent)
        nb.add(net_frame, text="  Red / Puertos  ")


if __name__ == "__main__":
    App().mainloop()
