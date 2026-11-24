"""StarPath 웹 시연 서버: 참여자별 화면을 나란히 띄워 각자 조작

실행: python web_demo.py  →  브라우저에서 http://127.0.0.1:8000

  - 팀은 A~E 5명(3-of-5). 화면 칸마다 참여자를 골라 놓고 그 사람의 입장에서 조작 (기본 3칸, 최대 5칸)
  - 화면에 없는 참여자는 키 준비 때 조각을 자동으로 받음
  - 시연용이라 모든 참여자 객체가 이 프로세스 하나에 있음 (실제로는 참여자마다 다른 기기)
  - 각 칸의 기록은 그 참여자가 한 계산의 진행 출력(shared.capture)
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import shared
import roles as sp
from keygen import rsa_keypair

HOST, PORT = "127.0.0.1", 8000
TEAM_ID, KEY_VERSION = "polygon", "k1"
MEMBER_IDS = list("ABCDE")
WEB_DIR = Path(__file__).with_name("web")


class Demo:
    def __init__(self) -> None:
        self.server = sp.Server()
        self.members = {mid: sp.Member(mid) for mid in MEMBER_IDS}
        self.rsa_keys: dict = {}                     # 참여자별 RSA 개인키 (각자 기기에 있다고 가정)
        self.inbox: dict[str, bytes] = {}
        self.requests: dict[int, dict] = {}
        self.logs: dict[str, list[str]] = {mid: [] for mid in MEMBER_IDS}
        self.dealer: str | None = None

    def run(self, mid: str, fn):
        with shared.capture() as lines:
            try:
                out = fn()
            except Exception as e:
                msg = e.args[0] if isinstance(e, KeyError) and e.args else e
                lines.append(f"✖ 거부: {msg}")
                out = None
        self.logs[mid].extend(lines)
        self.logs[mid].append("")
        return out

    def deal(self, mid: str, visible: list[str]) -> None:
        def go():
            if self.dealer is not None:
                raise PermissionError("이미 키 준비가 끝남 (키 준비는 팀 결성 때 한 번)")
            grp = sp.group()
            numbers = sp.assign_numbers(MEMBER_IDS, grp)
            for other in MEMBER_IDS:
                if other != mid and other not in self.rsa_keys:
                    self.rsa_keys[other] = rsa_keypair()
            pubs = {o: self.rsa_keys[o].public_key() for o in MEMBER_IDS if o != mid}
            team, sealed = self.members[mid].deal(TEAM_ID, KEY_VERSION, numbers, pubs, grp)
            self.server.register_team(team)
            self.dealer = mid
            self.inbox.update(sealed)
            hidden = [o for o in sealed if o not in visible]
            if hidden:
                shared.say(1, f"  (화면에 없는 {', '.join(hidden)}는 자동으로 조각을 받음)")
            return hidden
        hidden = self.run(mid, go) or []
        for o in hidden:
            self.receive(o)

    def receive(self, mid: str) -> None:
        def go():
            if mid not in self.inbox:
                raise PermissionError("받은 봉인 조각이 없음")
            shared.say(1, f"══ 조각 수신 ({mid}) ══")
            self.members[mid].receive_share(self.server, TEAM_ID, self.rsa_keys[mid], self.inbox[mid])
            del self.inbox[mid]
        self.run(mid, go)

    def write(self, mid: str, doc_id: str, text: str) -> None:
        def go():
            if not doc_id or not text:
                raise ValueError("문서 ID와 내용을 입력해야 함")
            versions = self.server.documents.get(doc_id, [])
            version = f"v{len(versions) + 1}"
            self.members[mid].write_document(self.server, TEAM_ID, doc_id, version, text.encode())
        self.run(mid, go)

    def request(self, mid: str, doc_id: str) -> None:
        def go():
            if doc_id not in self.server.documents:
                raise KeyError(f"저장된 문서가 아님: {doc_id or '(빈 ID)'}")
            req = self.members[mid].begin_open(self.server, TEAM_ID, doc_id)
            self.requests[req.request_no] = {"req": req, "responses": [], "result": None}
            shared.say(1, f"  요청 #{req.request_no} 게시 → 다른 참여자의 응답을 기다림")
        self.run(mid, go)

    def respond(self, mid: str, no: int) -> None:
        def go():
            item = self.requests.get(no)
            if item is None:
                raise KeyError(f"요청 #{no} 없음")
            req = item["req"]
            if req.requester_id == mid:
                raise PermissionError("요청자 자신의 값은 결합 때 직접 넣음")
            shared.say(1, f"══ 부분 복호 응답 ({mid} → 요청 #{no}, 요청자 {req.requester_id}) ══")
            shared.say(1, f"  받은 값 B={sp.show(req.b_req)} (C1·t·Z는 모름)")
            item["responses"].append(self.members[mid].respond(self.server, req))
        self.run(mid, go)

    def finish(self, mid: str, no: int) -> None:
        def go():
            item = self.requests.get(no)
            if item is None:
                raise KeyError(f"요청 #{no} 없음")
            need = sp.THRESHOLD - (1 if self.members[mid].has_share_for(TEAM_ID) else 0)
            if item["req"].requester_id == mid and len(item["responses"]) < need:
                raise PermissionError(f"협력자 응답 {len(item['responses'])}명: {need}명이 모일 때까지 기다림 (요청은 유지)")
            shared.say(1, f"══ 결합·복호 (요청 #{no}, 응답 {len(item['responses'])}명) ══")
            pt = self.members[mid].finish_open(self.server, item["req"], item["responses"])
            item["result"] = pt.decode("utf-8", "replace")
            shared.say(1, f"  ▶ 복원 결과: {item['result']}")
        self.run(mid, go)

    def state(self) -> dict:
        team = self.server.teams.get(TEAM_ID)
        docs = [{"doc_id": r.doc_id, "version": r.version, "author": r.author_id,
                 "C1": sp.show(r.C1), "ct": sp.show(r.ciphertext), "tag": sp.show(r.tag)}
                for recs in self.server.documents.values() for r in recs]
        reqs = [{"no": no, "requester": it["req"].requester_id, "doc_id": it["req"].doc_id,
                 "version": it["req"].version, "B": sp.show(it["req"].b_req),
                 "responders": [r.member_id for r in it["responses"]],
                 "result": it["result"],
                 "open": it["req"].request_no in self.members[it["req"].requester_id]._open}
                for no, it in self.requests.items()]
        return {
            "threshold": sp.THRESHOLD, "n": sp.N_MEMBERS, "trace": shared.TRACE_LEVEL,
            "dealer": self.dealer,
            "team": None if team is None else {
                "Y": sp.show(team.Y), "key_version": team.key_version,
                "members": {m.member_id: {"x": m.x, "y": sp.show(m.y)} for m in team.members.values()}},
            "members": {mid: {"has_share": self.members[mid].has_share_for(TEAM_ID),
                              "inbox": mid in self.inbox,
                              "answered": sorted(self.members[mid]._answered),
                              "log": self.logs[mid]} for mid in MEMBER_IDS},
            "documents": docs,
            "requests": reqs,
        }


demo = Demo()
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj) -> None:
        self._send(200, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(200, (WEB_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            with lock:
                self._json(demo.state())
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        global demo
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        mid = body.get("member")
        if mid is not None and mid not in MEMBER_IDS:
            return self._send(400, b"bad member", "text/plain")
        with lock:
            match self.path:
                case "/api/reset":
                    demo = Demo()
                case "/api/trace":
                    sp.set_trace(int(body.get("level", 1)))
                case "/api/deal":
                    demo.deal(mid, body.get("visible", []))
                case "/api/receive":
                    demo.receive(mid)
                case "/api/write":
                    demo.write(mid, body.get("doc_id", "").strip(), body.get("text", ""))
                case "/api/request":
                    demo.request(mid, body.get("doc_id", ""))
                case "/api/respond":
                    demo.respond(mid, int(body["no"]))
                case "/api/finish":
                    demo.finish(mid, int(body["no"]))
                case _:
                    return self._send(404, b"not found", "text/plain")
            self._json(demo.state())


def main() -> None:
    sp.set_trace(1)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"StarPath 시연: http://{HOST}:{PORT}  (종료: Ctrl+C)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
