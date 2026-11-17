import json
import sqlite3

from app.parsers import parse_file


def test_jsonl_claude_messages(tmp_path):
    p = tmp_path / ".claude" / "projects" / "x" / "s.jsonl"
    p.parent.mkdir(parents=True)
    lines = [
        {"type": "user", "timestamp": "2026-11-05T12:00:00Z",
         "message": {"role": "user", "content": "qual o client id do sicoob?"}},
        {"type": "assistant", "timestamp": "2026-11-05T12:00:05Z",
         "message": {"role": "assistant", "content": [{"type": "text", "text": "use o portal"}]}},
        "linha quebrada {",
    ]
    p.write_text("\n".join(json.dumps(x) if isinstance(x, dict) else x for x in lines))
    events = parse_file(p, "ia")
    texts = [e.text for e in events]
    assert "qual o client id do sicoob?" in texts
    assert "use o portal" in texts
    assert events[0].role == "user"
    assert events[0].ts == "2026-11-05T12:00:00Z"


def test_generic_json_extracts_strings(tmp_path):
    p = tmp_path / "chat.json"
    p.write_text(json.dumps({"messages": [{"role": "user", "text": "manda o pfx"}]}))
    assert any("manda o pfx" in e.text for e in parse_file(p, "ia"))


def test_vscdb_itemtable(tmp_path):
    p = tmp_path / "state.vscdb"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE ItemTable (key TEXT, value BLOB)")
    con.execute("INSERT INTO ItemTable VALUES (?, ?)",
                ("workbench.panel.aichat.view.aichat.chatdata",
                 json.dumps({"tabs": [{"bubbles": [{"text": "chave sk-or-v1-xyz"}]}]})))
    con.execute("INSERT INTO ItemTable VALUES (?, ?)", ("theme", "dark"))
    con.commit(); con.close()
    events = parse_file(p, "ia")
    assert any("sk-or-v1-xyz" in e.text for e in events)
    assert not any(e.text == "dark" for e in events)


def test_anydesk_trace_connection(tmp_path):
    p = tmp_path / "connection_trace.txt"
    p.write_text("Incoming    2026-11-05, 15:11    User    123456789    987654321\n")
    events = parse_file(p, "acesso_remoto")
    assert events and events[0].source == "anydesk"
    assert "123456789" in events[0].text


def test_teamviewer_connections(tmp_path):
    p = tmp_path / "Connections_incoming.txt"
    p.write_text("1234567890\tJOAO-PC\t05-11-2026 15:10:00\t05-11-2026 15:40:00\tsuporte\tRemoteControl\t{guid}\n")
    events = parse_file(p, "acesso_remoto")
    assert events[0].source == "teamviewer"
    assert "JOAO-PC" in events[0].text


def test_rustdesk_log_filters_connection_lines(tmp_path):
    p = tmp_path / "RustDesk" / "log" / "server" / "rustdesk_rCURRENT.log"
    p.parent.mkdir(parents=True)
    p.write_text("[2026-11-05 15:15:00] INFO heartbeat ok\n"
                 "[2026-11-05 15:16:00] INFO Connection opened from 187.32.194.41:5555\n")
    events = parse_file(p, "acesso_remoto")
    assert len(events) == 1
    assert events[0].source == "rustdesk"
    assert "187.32.194.41" in events[0].text


def test_binary_or_unknown_is_skipped(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01\x02")
    assert parse_file(p, "ia") == []
