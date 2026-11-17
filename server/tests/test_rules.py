from app.masking import fingerprint, mask
from app.rules import load_rules, scan_text

RULES = load_rules()


def kinds(text):
    return {f.rule_id for f in scan_text(text, RULES)}


def test_mask_keeps_prefix_and_tail():
    assert mask("sk-or-v1-abcdef0123456789abcdef") == "sk-or-…cdef"
    assert "abcdef0123" not in mask("sk-or-v1-abcdef0123456789abcdef")


def test_mask_short_value_fully_hidden():
    assert mask("abc") == "…"


def test_fingerprint_stable_and_distinct():
    assert fingerprint("x") == fingerprint("x")
    assert fingerprint("x") != fingerprint("y")
    assert len(fingerprint("x")) == 16


def test_detects_openrouter_key():
    assert "openrouter_key" in kinds("export OPENROUTER_API_KEY=sk-or-v1-" + "a1" * 32)


def test_detects_anthropic_and_jwt():
    assert "anthropic_key" in kinds("key sk-ant-api03-" + "Z" * 40)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123_-xyz"
    assert "jwt" in kinds(f"token {jwt}")


def test_detects_client_id_with_context():
    assert "client_id" in kinds("Client ID= 17e5473d-9791-4a4b-a347-78b5e23733d8")


def test_bare_uuid_without_context_ignored():
    assert "client_id" not in kinds("trace 17e5473d-9791-4a4b-a347-78b5e23733d8")


def test_detects_private_key_block():
    assert "private_key" in kinds("-----BEGIN PRIVATE KEY-----\nMIIE")


def test_fraud_keywords_ptbr():
    found = scan_text("manda pra conta laranja e não conta pra ninguém", RULES)
    ids = {f.rule_id for f in found}
    assert "fraude_laranja" in ids
    assert all(f.category == "fraude" for f in found if f.rule_id.startswith("fraude_"))


def test_benign_text_clean():
    assert kinds("vamos ajustar o layout do relatório de vendas amanhã") == set()


def test_finding_carries_masked_value_and_fingerprint():
    key = "sk-or-v1-" + "b2" * 32
    f = next(x for x in scan_text(key, RULES) if x.rule_id == "openrouter_key")
    assert f.masked == mask(key)
    assert f.fingerprint == fingerprint(key)
    assert key not in f.snippet
