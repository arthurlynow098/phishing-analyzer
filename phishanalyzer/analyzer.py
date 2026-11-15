"""Análise de um e-mail salvo como .eml.

Cada verificação devolve um "sinal" com peso. A soma vira uma nota de risco.
Nenhum sinal sozinho prova golpe, mas vários juntos quase sempre provam.
"""
from __future__ import annotations

import email
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

URGENCY = [
    "urgente", "imediatamente", "bloqueada", "bloqueio", "suspensa", "suspenso", "última chance",
    "verifique sua conta", "atualize seus dados", "confirme seus dados", "clique aqui", "expira hoje",
    "pendência", "regularize", "evite o cancelamento", "senha expirada",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "encurtador.com.br", "rebrand.ly"}
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso", ".img", ".html", ".htm", ".zip", ".rar")
BRANDS = ["itau", "bradesco", "nubank", "caixa", "santander", "bancodobrasil", "mercadolivre",
          "microsoft", "netflix", "correios", "receita", "gov", "paypal", "apple", "amazon"]


@dataclass
class Signal:
    weight: int
    title: str
    detail: str


@dataclass
class Report:
    subject: str
    sender: str
    reply_to: str
    links: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)
    signals: list[Signal] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(s.weight for s in self.signals))

    @property
    def verdict(self) -> str:
        if self.score >= 60:
            return "muito provavelmente phishing"
        if self.score >= 30:
            return "suspeito, trate com cuidado"
        return "sem sinais fortes"


class _LinkCollector(HTMLParser):
    """Guarda pares (texto que aparece, endereço real) de cada <a>."""

    def __init__(self):
        super().__init__()
        self.pairs: list[tuple[str, str]] = []
        self._href = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.pairs.append(("".join(self._text).strip(), self._href))
            self._href = None


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">") if "@" in address else ""


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def parse_auth_results(msg) -> dict[str, str]:
    """Lê o cabeçalho Authentication-Results que o servidor de quem recebeu escreveu."""
    header = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        hit = re.search(rf"\b{mech}=(\w+)", header, re.I)
        out[mech] = hit.group(1).lower() if hit else "ausente"
    return out


def check_url(url: str, sender_domain: str) -> list[Signal]:
    signals = []
    host = host_of(url)
    if not host:
        return signals
    try:
        ipaddress.ip_address(host)
        signals.append(Signal(20, "link aponta para um IP", url))
    except ValueError:
        pass
    if host in SHORTENERS:
        signals.append(Signal(10, "link encurtado esconde o destino", url))
    if host.startswith("xn--") or ".xn--" in host:
        signals.append(Signal(20, "domínio com punycode, pode imitar letras", url))
    if host.count("-") >= 3 or host.count(".") >= 4:
        signals.append(Signal(8, "domínio com cara de gerado", host))
    squashed = host.replace("-", "").replace(".", "")
    for brand in BRANDS:
        if brand in squashed and not (host.endswith(f"{brand}.com.br") or host.endswith(f"{brand}.com")
                                      or host.endswith(f"{brand}.gov.br")):
            signals.append(Signal(20, f"usa o nome {brand} num domínio que não é da marca", host))
            break
    if url.lower().startswith("http://"):
        signals.append(Signal(5, "link sem HTTPS", url))
    return signals


def analyze_message(raw: bytes) -> Report:
    msg = email.message_from_bytes(raw, policy=policy.default)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    rep = Report(str(msg.get("Subject", "")), f"{from_name} <{from_addr}>".strip(), reply_addr)
    sender_domain = domain_of(from_addr)

    rep.auth = parse_auth_results(msg)
    for mech, result in rep.auth.items():
        if result in ("fail", "softfail", "permerror"):
            rep.signals.append(Signal(25 if mech == "dmarc" else 15, f"{mech.upper()} falhou", result))
        elif result == "ausente":
            rep.signals.append(Signal(3, f"sem resultado de {mech.upper()}", "não dá para confirmar o remetente"))

    if reply_addr and domain_of(reply_addr) != sender_domain:
        rep.signals.append(Signal(20, "Reply-To diferente do remetente", f"a resposta vai para {reply_addr}"))
    if return_path and domain_of(return_path) != sender_domain:
        rep.signals.append(Signal(10, "Return-Path de outro domínio", return_path))
    for brand in BRANDS:
        if brand in from_name.lower().replace(" ", "") and brand not in sender_domain:
            rep.signals.append(Signal(20, "nome de exibição imita uma marca", f"{from_name} usando {sender_domain}"))
            break

    text_parts, html_parts = [], []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            rep.attachments.append(filename)
            if filename.lower().endswith(RISKY_EXT):
                rep.signals.append(Signal(25, "anexo de tipo perigoso", filename))
            if re.search(r"\.(pdf|docx?|xlsx?|jpg)\.\w+$", filename, re.I):
                rep.signals.append(Signal(20, "extensão dupla no anexo", filename))
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text_parts.append(part.get_content())
        elif ctype == "text/html":
            html_parts.append(part.get_content())

    body = "\n".join(text_parts + html_parts)
    found_urls = set(re.findall(r"https?://[^\s\"'<>]+", body))
    for html in html_parts:
        collector = _LinkCollector()
        collector.feed(html)
        for text, href in collector.pairs:
            found_urls.add(href)
            shown = host_of(text if text.startswith("http") else f"http://{text}") if "." in text else ""
            if shown and host_of(href) and shown != host_of(href):
                rep.signals.append(Signal(25, "texto do link mostra um site e leva para outro",
                                          f"mostra {shown} e abre {host_of(href)}"))
    rep.links = sorted(u for u in found_urls if u.startswith("http"))
    for url in rep.links:
        rep.signals.extend(check_url(url, sender_domain))

    lowered = (rep.subject + " " + body).lower()
    hits = [w for w in URGENCY if w in lowered]
    if hits:
        rep.signals.append(Signal(min(20, 5 * len(hits)), "linguagem de urgência ou ameaça", ", ".join(hits[:5])))
    return rep
