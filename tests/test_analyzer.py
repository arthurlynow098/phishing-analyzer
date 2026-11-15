from pathlib import Path

from phishanalyzer.analyzer import analyze_message, check_url

EX = Path(__file__).resolve().parent.parent / "exemplos"


def titles(rep):
    return {s.title for s in rep.signals}


def test_email_suspeito_tem_nota_alta():
    rep = analyze_message((EX / "suspeito.eml").read_bytes())
    assert rep.score >= 60
    assert rep.auth == {"spf": "softfail", "dkim": "none", "dmarc": "fail"}
    t = titles(rep)
    assert "DMARC falhou" in t
    assert "Reply-To diferente do remetente" in t
    assert "texto do link mostra um site e leva para outro" in t
    assert "extensão dupla no anexo" in t


def test_email_legitimo_passa():
    rep = analyze_message((EX / "legitimo.eml").read_bytes())
    assert rep.score < 30
    assert rep.verdict == "sem sinais fortes"


def test_link_com_ip_e_encurtador():
    assert any("IP" in s.title for s in check_url("http://192.0.2.4/login", "x.example"))
    assert any("encurtado" in s.title for s in check_url("https://bit.ly/abc", "x.example"))


def test_marca_em_dominio_errado():
    sinais = check_url("https://itau-atualizacao.example/", "x.example")
    assert any("itau" in s.title for s in sinais)
    assert check_url("https://www.itau.com.br/", "itau.com.br") == []
