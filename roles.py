"""StarPath 역할: 서버(공개 정보·암호문 보관)와 참여자(배포자·수신자·작성자·요청자·협력자)

알고리즘은 파일별로 나뉘어 있음
  shared.py  : 진행 출력, [미정] 표시, 상수, 군, 블록 규격, HKDF·키 유도, 문서 레코드·MAC
  keygen.py  : 키 생성 (Shamir 조각, Y, y_i, RSA-OAEP 조각 전달)
  encrypt.py : 암호화 (C1·Z, SPN·CBC, HMAC)
  decrypt.py : 복호화 (블라인딩, 부분 복호·증명, 라그랑주 결합, SPN 역연산)
이 파일은 누가 무엇을 할 수 있는지(역할 분리)만 다루고 계산은 위 파일에 맡긴다.
[미정] 목록은 shared.py 머리말 참고.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric import rsa

from shared import (KNOWN_BLOCKS, N_MEMBERS, PROVISIONAL, REAL_BLOCK, REAL_GROUP, THRESHOLD, BlockSpec,
                    DocumentRecord, Group, ProvisionalWarning, VerificationError, capture, group,
                    provisional, say, set_trace, show)
from decrypt import blind, decrypt_document, partial_decrypt, make_proof, recover_z, verify_partial
from encrypt import encrypt_document
from keygen import assign_numbers, check_numbers, generate_team_key, open_share, rsa_keypair, seal_share

__all__ = [
    "N_MEMBERS", "THRESHOLD", "PROVISIONAL", "REAL_BLOCK", "REAL_GROUP", "BlockSpec", "Group",
    "ProvisionalWarning", "VerificationError", "capture", "group", "set_trace", "show",
    "assign_numbers", "rsa_keypair", "authenticate", "MemberPublic", "TeamPublic", "DocumentRecord",
    "OpenRequest", "PartialDecryption", "Server", "Member", "select_partials", "pick_threshold",
]


@provisional("신원 확인 없이 통과 (보안 기능 없음, 밝힌 ID를 그대로 믿음)")
def authenticate(team: "TeamPublic", member_id: str, message: object) -> None:
    return None


@dataclass(frozen=True)
class MemberPublic:
    member_id: str
    x: int
    y: int                  # 검증 공개키 g^{s_i}


@dataclass(frozen=True)
class TeamPublic:
    team_id: str
    key_version: str
    grp: Group
    Y: int
    members: dict[str, MemberPublic]

    def validate(self) -> None:
        self.grp.check()
        check_numbers({m.member_id: m.x for m in self.members.values()}, self.grp)
        if any(mid != m.member_id for mid, m in self.members.items()):
            raise VerificationError("참여자 ID 불일치")
        self.grp.require_element(self.Y, "팀 공개키 Y")
        for m in self.members.values():
            self.grp.require_element(m.y, f"검증 공개키 y_{m.member_id}", allow_identity=True)


@dataclass(frozen=True)
class OpenRequest:
    """협력자에게 보내는 공개 요청. 블라인딩 값 t는 들어 있지 않음"""
    request_no: int
    team_id: str
    requester_id: str
    doc_id: str
    version: str
    b_req: int


@dataclass(frozen=True)
class PartialDecryption:
    member_id: str
    d: int
    proof: object


@dataclass
class Server:
    """공개 정보와 암호문만 보관. 조각·k·Z·t는 다루지 않음"""
    teams: dict[str, TeamPublic] = field(default_factory=dict)
    documents: dict[str, list[DocumentRecord]] = field(default_factory=dict)

    def register_team(self, team: TeamPublic) -> None:
        if team.team_id in self.teams:
            raise PermissionError("이미 등록된 팀 (키 준비는 팀 결성 때 한 번)")
        team.validate()
        self.teams[team.team_id] = team
        say(1, f"  서버 등록: 팀 {team.team_id}, 키 버전 {team.key_version}, Y, 번호 x_i, 검증 공개키 y_i")

    def team(self, team_id: str) -> TeamPublic:
        if team_id not in self.teams:
            raise PermissionError(f"등록되지 않은 팀: {team_id}")
        return self.teams[team_id]

    def store(self, rec: DocumentRecord) -> None:
        team = self.team(rec.team_id)
        if rec.key_version != team.key_version:
            raise VerificationError("문서의 키 버전이 팀 키 버전과 다름")
        if rec.author_id not in team.members:
            raise PermissionError("팀 참여자만 문서를 저장할 수 있음")
        if rec.block not in KNOWN_BLOCKS:
            raise VerificationError("허용되지 않은 블록 규격")
        team.grp.require_element(rec.C1, "C1")
        if any(r.version == rec.version for r in self.documents.get(rec.doc_id, [])):
            raise PermissionError("같은 문서 버전이 이미 있음")
        authenticate(team, rec.author_id, rec)
        self.documents.setdefault(rec.doc_id, []).append(rec)
        say(1, f"  서버 저장: C1, salt, info, IV, 암호문, 태그 (k·Z는 저장하지 않음)")

    def get(self, doc_id: str, version: str | None = None) -> DocumentRecord:
        recs = self.documents.get(doc_id)
        if not recs:
            raise KeyError(doc_id)
        if version is None:
            return recs[-1]
        for r in recs:
            if r.version == version:
                return r
        raise KeyError((doc_id, version))


@provisional("τ명보다 많이 통과하면 요청자 값을 먼저, 나머지는 응답 순서대로 τ명")
def pick_threshold(valid: list[PartialDecryption], requester_id: str) -> list[PartialDecryption]:
    own = [r for r in valid if r.member_id == requester_id]
    return (own + [r for r in valid if r.member_id != requester_id])[:THRESHOLD]


def select_partials(team: TeamPublic, req: OpenRequest, requester_has_share: bool,
                    responses: Sequence[PartialDecryption]) -> list[PartialDecryption]:
    """검증을 통과한 정확히 τ명, 요청자가 조각을 가졌다면 자신의 값 포함"""
    grp, valid, seen = team.grp, [], set()
    for r in responses:
        if r.member_id in seen or r.member_id not in team.members:
            continue
        try:
            grp.require_element(r.d, f"d_{r.member_id}", allow_identity=True)
            verify_partial(grp, req.b_req, team.members[r.member_id].y, r.d, r.proof)
        except VerificationError as e:
            say(1, f"    {r.member_id}: 증명 검증 실패 → 제외 ({e})")
            continue
        say(1, f"    {r.member_id}: 증명 검증 통과")
        seen.add(r.member_id)
        valid.append(r)
    # [직접 설계] 요청자 값 포함, 3명 미만이면 거부, 4명 이상이어도 3명만 골라 결합
    if requester_has_share and req.requester_id not in seen:
        raise VerificationError("요청자가 조각을 가졌다면 자신의 부분 복호값을 포함해야 함")
    if len(valid) < THRESHOLD:
        raise PermissionError(f"검증 통과 {len(valid)}명: {THRESHOLD}명 미만이라 복호 거부")
    chosen = pick_threshold(valid, req.requester_id) if len(valid) > THRESHOLD else valid
    say(1, f"  결합 대상 {THRESHOLD}명: {', '.join(p.member_id for p in chosen)}")
    return chosen


_request_numbers = count(1)


class Member:
    def __init__(self, member_id: str):
        self.member_id = member_id
        self._share: int | None = None
        self._team_id: str | None = None
        self._open: dict[int, tuple[DocumentRecord, int]] = {}   # 요청 번호 → (문서, 블라인딩 t)
        self._answered: set[int] = set()

    def has_share_for(self, team_id: str) -> bool:
        return self._share is not None and self._team_id == team_id

    # ── 배포자 ──────────────────────────────────────────────────────────────
    def deal(self, team_id: str, key_version: str, numbers: dict[str, int],
             recipient_public_keys: dict[str, rsa.RSAPublicKey],
             grp: Group | None = None) -> tuple[TeamPublic, dict[str, bytes]]:
        """팀 비밀 s와 계수를 만들고 조각을 나눔

        numbers               : 참여자 ID → 번호 (배포자가 지정). 배포자 본인 포함
        recipient_public_keys : 다른 참여자들의 RSA 공개키
        반환                 : (서버에 등록할 공개 정보, 다른 참여자별 봉인된 조각)
        배포자 자신의 조각은 이 객체에 바로 보관하고, s·계수는 함수가 끝나면 버림
        """
        if self._share is not None:
            raise PermissionError("이미 조각을 보관 중 (키 준비는 팀 결성 때 한 번)")
        grp = grp or group()
        if self.member_id not in numbers:
            raise ValueError("배포자도 참여자 번호가 있어야 함")
        # [직접 설계] 번호 배정 → RSA-OAEP로 (번호, 조각) 전달 → 자기 조각만 남기고 s·계수·다른 조각 폐기
        check_numbers(numbers, grp)
        others = [mid for mid in numbers if mid != self.member_id]
        if set(recipient_public_keys) != set(others):
            raise ValueError("배포자를 뺀 모든 참여자의 공개키가 필요함")

        say(1, f"══ 초기 설정 (배포자 {self.member_id}) ══")
        Y, shares, ys = generate_team_key(grp, numbers)
        team = TeamPublic(team_id, key_version, grp, Y,
                          {mid: MemberPublic(mid, numbers[mid], ys[mid]) for mid in numbers})
        team.validate()
        sealed = {mid: seal_share(recipient_public_keys[mid], numbers[mid], shares[mid]) for mid in others}
        for mid in others:
            say(1, f"  {mid}에게 RSA-OAEP(PK_{mid}, ({numbers[mid]}, s_{mid})) 전송: {show(sealed[mid])}")
        self._share, self._team_id = shares[self.member_id], team_id
        shares.clear()
        say(1, f"  배포자 {self.member_id}: 자기 조각만 보관하고 s·계수·다른 조각 폐기")
        return team, sealed

    # ── 수신자 ──────────────────────────────────────────────────────────────
    def receive_share(self, server: Server, team_id: str, private_key: rsa.RSAPrivateKey,
                      sealed: bytes) -> None:
        """봉인된 (번호, 조각)을 열어 등록 정보와 맞는지 확인 후 보관"""
        if self._share is not None:
            raise PermissionError("이미 조각을 보관 중 (덮어쓰기 금지)")
        team = server.team(team_id)
        if self.member_id not in team.members:
            raise PermissionError("이 팀의 참여자가 아님")
        x, s_i = open_share(private_key, sealed)
        grp, me = team.grp, team.members[self.member_id]
        # [직접 설계] 받은 조각을 서버에 등록된 번호·검증 공개키와 대조한 뒤 보관
        if x != me.x or not 0 <= s_i < grp.q or pow(grp.g, s_i, grp.p) != me.y:
            raise VerificationError("받은 (번호, 조각)이 등록된 공개 정보와 맞지 않음")
        self._share, self._team_id = s_i, team.team_id
        say(1, f"  {self.member_id}: 봉인 열기 → x={x}, [비밀] s_{self.member_id}={show(s_i)}, "
               f"g^s = y_{self.member_id} 확인 후 보관")

    # ── 작성자 ──────────────────────────────────────────────────────────────
    def write_document(self, server: Server, team_id: str, doc_id: str, version: str,
                       plaintext: bytes, block: BlockSpec = REAL_BLOCK) -> DocumentRecord:
        """k와 Z는 이 메서드 밖으로 나가지 않음"""
        team = server.team(team_id)
        if self.member_id not in team.members:
            raise PermissionError("팀 참여자만 문서를 작성할 수 있음")
        if block not in KNOWN_BLOCKS:
            raise ValueError("허용되지 않은 블록 규격")
        say(1, f"══ 암호화 (작성자 {self.member_id}, 문서 {doc_id} {version}) ══")
        rec = encrypt_document(team.grp, team.Y, team_id, doc_id, version, team.key_version,
                               self.member_id, plaintext, block)
        server.store(rec)
        return rec

    # ── 요청자 ──────────────────────────────────────────────────────────────
    def begin_open(self, server: Server, team_id: str, doc_id: str,
                   version: str | None = None) -> OpenRequest:
        """블라인딩 값 t를 이 객체에만 보관하고, 협력자에게 보낼 요청을 돌려줌"""
        team = server.team(team_id)
        if self.member_id not in team.members:
            raise PermissionError("팀 참여자만 복호를 요청할 수 있음")
        record = server.get(doc_id, version)
        if record.team_id != team_id or record.key_version != team.key_version:
            raise VerificationError("문서의 팀 또는 키 버전이 다름")
        grp = team.grp
        grp.require_element(record.C1, "C1")
        say(1, f"══ 복호화 (요청자 {self.member_id}, 문서 {record.doc_id} {record.version}) ══")
        say(1, f"  서버에서 C1={show(record.C1)} 조회")
        # [직접 설계] C1을 그대로 보내지 않고 B = C1·g^t로 가려서 보냄 (t는 요청자만 보관)
        while True:
            t = grp.rand_scalar()
            b = blind(grp, record.C1, t)
            if b != 1:                                  # t ≡ −k 이면 B = 1이 되어 협력자가 거부함
                break
        say(1, f"  [비밀] 블라인딩 난수 t={show(t)}")
        say(1, f"  B = C1·g^t mod p = {show(b)}  → 협력자에게 B만 보냄 (C1·t는 보내지 않음)")
        req = OpenRequest(next(_request_numbers), team_id, self.member_id, record.doc_id, record.version, b)
        self._open[req.request_no] = (record, t)
        return req

    def finish_open(self, server: Server, req: OpenRequest,
                    helper_responses: Sequence[PartialDecryption]) -> bytes:
        """협력자 응답 + 자기 부분 복호값 → 검증 → 결합 → t 제거 → MAC 확인 → 키 유도 → 복호"""
        if req.requester_id != self.member_id or req.request_no not in self._open:
            raise PermissionError("내가 만든 요청이 아님")
        record, t = self._open.pop(req.request_no)
        team = server.team(req.team_id)
        grp = team.grp
        has_share = self.has_share_for(team.team_id)
        responses = list(helper_responses)
        # [직접 설계] 요청자도 조각이 있으면 자기 부분 복호값을 결합에 넣음
        if has_share:
            responses.insert(0, self.respond(server, req))
        say(1, "  부분 복호값 검증")
        chosen = select_partials(team, req, has_share, responses)

        partials = [(p.member_id, team.members[p.member_id].x, p.d) for p in chosen]
        z = recover_z(grp, team.Y, t, partials)
        del t
        return decrypt_document(grp, z, record)

    def open_document(self, server: Server, team_id: str, doc_id: str,
                      helpers: Sequence["Member"], version: str | None = None) -> bytes:
        """요청 → 협력자 응답 수집 → 복원을 한 번에"""
        req = self.begin_open(server, team_id, doc_id, version)
        try:
            return self.finish_open(server, req, [h.respond(server, req) for h in helpers if h is not self])
        finally:
            self._open.pop(req.request_no, None)

    # ── 협력자 ──────────────────────────────────────────────────────────────
    def respond(self, server: Server, req: OpenRequest) -> PartialDecryption:
        """요청값 B에 자기 조각을 적용. B만 보며 C1·t·Z는 모름"""
        if not self.has_share_for(req.team_id):
            raise PermissionError("이 팀의 조각이 없음")
        team = server.team(req.team_id)
        if req.requester_id not in team.members:
            raise PermissionError("팀 참여자가 아닌 요청자")
        record = server.get(req.doc_id, req.version)
        if record.team_id != req.team_id:
            raise PermissionError("다른 팀의 문서에 대한 요청")
        if req.request_no in self._answered:
            raise PermissionError("이미 응답한 요청")
        authenticate(team, req.requester_id, req)
        grp = team.grp
        grp.require_element(req.b_req, "B_req")
        self._answered.add(req.request_no)
        # [직접 설계] 협력자는 B에만 조각을 적용 (어느 문서의 C1인지, Z는 모름)
        d = partial_decrypt(grp, req.b_req, self._share)
        proof = make_proof(grp, req.b_req, self._share, d)
        say(1, f"  {self.member_id}: d_{self.member_id} = B^s_{self.member_id} mod p = {show(d)}, "
               f"증명 (c={show(proof[0])}, z={show(proof[1])})")
        return PartialDecryption(self.member_id, d, proof)
