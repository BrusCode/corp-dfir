from app import parsers
from app.remote import classify_remote_line


def lines(tmp_path, name, text, folder=""):
    d = tmp_path / folder if folder else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(text)
    return parsers.parse_file(p, "acesso_remoto")


def test_teamviewer_service_noise_dropped(tmp_path):
    ev = lines(tmp_path, "TeamViewer15_Logfile.log",
               "2026/10/19 10:42:39.526 5508 5512 S0 SERVICE_CONTROL_SESSIONCHANGE session=2, statusCode=WTS_SESSION_LOCK\n"
               "2026/10/19 11:04:01.783 5508 4724 S0 NetWatchdog: Internet is now disconnected\n"
               "2026/10/19 11:10:00.000 5508 4724 S0 CarrierInfo: incoming connection from 1234567890\n")
    assert len(ev) == 1 and "1234567890" in ev[0].text


def test_webposto_agent_is_identified_as_ours(tmp_path):
    ev = lines(tmp_path, "webPosto-Agente_rCURRENT.log",
               "[2026-11-05 15:16:00] INFO Connection opened from 187.32.194.41:5555\n"
               "[2026-11-05 15:16:01] INFO heartbeat\n",
               folder="AppData/Roaming/webPosto-Agente/log/server")
    assert len(ev) == 1 and ev[0].source == "webposto-agente"


def test_classification():
    assert classify_remote_line("anydesk", "Incoming session request: Joao (123456789)") == ("acesso_remoto_sessao", "baixa")
    assert classify_remote_line("rustdesk", "Connection opened from 1.2.3.4") == ("acesso_remoto_sessao", "baixa")
    assert classify_remote_line("teamviewer", "FileTransfer: send file bonanza.pfx") == ("acesso_remoto_arquivo", "media")
    assert classify_remote_line("anydesk", "network: connected to relay") is None


def test_pipeline_does_not_flag_every_tool_mention(settings, tmp_path):
    import hashlib, json, zipfile
    from app import config, db
    from app.pipeline import process_bundle
    trace = (b"info 2026-11-05 15:11:00 anydesk network: connected to relay\n"
             b"info 2026-11-05 15:12:00 anydesk Incoming session request: X (123456789)\n")
    z = tmp_path / "b.zip"
    m = [{"profile": "k", "category": "acesso_remoto", "original_path": r"C:\Users\k\AppData\Roaming\AnyDesk\ad.trace",
          "archive_path": "files/ad.trace", "size": len(trace), "sha256": hashlib.sha256(trace).hexdigest(), "status": "copied"}]
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("files/ad.trace", trace)
        zf.writestr("manifest.json", json.dumps(m))
        zf.writestr("custody.json", "{}")
    cid = db.create_collection(config.get_settings(), host="H", filename="b.zip", sha256="r" * 64,
                               stored_path=str(z), custody={})
    process_bundle(config.get_settings(), cid)
    rules = [f["rule_id"] for f in db.list_findings(config.get_settings(), collection_id=cid)]
    assert rules == ["acesso_remoto_sessao"]
