"""
StarPath 구현

역할은 모두 Member의 메서드입니다. 누구나 어느 역할이든 맡을 수 있습니다.
  deal()            배포자 : 비밀·계수 생성, 조각 계산, 자기 조각 보관, 나머지 조각 봉인
  receive_share()   수신자 : 봉인된 (번호, 조각)을 열어 등록 정보와 대조 후 보관
  write_document()  작성자 : k, C1, Z → 키 유도 → 본문 암호화 → 레코드
  begin_open()      요청자 : 블라인딩 값 t 생성·보관, 요청값 B 공개
  respond()         협력자 : B에 자기 조각을 적용한 부분 복호값 응답
  finish_open()     요청자 : 자기 값 포함 τ명 결합 → t 제거 → 키 유도 → 복호
  open_document()   요청자 : begin_open → 협력자 respond → finish_open 한 번에
비밀값(조각 s_i, 블라인딩 t)은 그 값을 가진 Member 객체 밖으로 나가지 않습니다.

[미정] 근거가 없어 비워 둔 부분 (호출하면 Unspecified 예외)
  1. group()                : 3072비트 안전 소수 p와 생성원 g의 값
  2. assign_numbers()       : 참여자 번호 배정 규칙
  3. rsa_keypair() / seal_share() / open_share() : RSA 키 크기, OAEP 해시, (번호, 조각) 인코딩
  4. new_salt()             : salt 길이·생성 방법
  5. derive_keys()          : HKDF 입력 인코딩, 라운드 키 13개 확장 방법
  6. pad() / unpad()        : CBC 패딩
  7. new_iv()               : IV 생성·저장
  8. mac_tag() / mac_verify(): HMAC 해시·키·적용 범위·입력 형식
  9. make_proof() / verify_partial() : Chaum–Pedersen 부분 복호 증명
 10. select_partials()      : τ명보다 많이 응답했을 때 결합할 τ명을 고르는 기준
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from itertools import count
from typing import Sequence

# ──────────────────────────────────────────────────────────────────────────────
# 0) 상수
# ──────────────────────────────────────────────────────────────────────────────
N_MEMBERS, THRESHOLD = 5, 3

BLOCK_BYTES = 16
BLOCK_BITS = BLOCK_BYTES * 8
BLOCK_NIBBLES = BLOCK_BYTES * 2
ROUNDS = 12
ROUND_KEY_COUNT = ROUNDS + 1

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
INV_SBOX = [SBOX.index(i) for i in range(16)]


class Unspecified(NotImplementedError):
    """설계 문서에 아직 규칙이 없는 부분"""


class VerificationError(ValueError):
    """입력값·조각·응답 검증 실패"""


# ──────────────────────────────────────────────────────────────────────────────
# 1) 군
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Group:
    """안전 소수 p = 2q+1, g는 위수 q 부분군의 원소."""
    p: int
    q: int
    g: int

    def check(self) -> None:
        if self.p != 2 * self.q + 1:
            raise VerificationError("p = 2q + 1 이 아님")
        if not (is_probable_prime(self.p) and is_probable_prime(self.q)):
            raise VerificationError("p 또는 q가 소수가 아님")
        if self.g in (0, 1) or pow(self.g, self.q, self.p) != 1:
            raise VerificationError("g가 위수 q 부분군에 있지 않음")

    def rand_scalar(self) -> int:
        """1 … q-1 범위의 균등 난수."""
        return secrets.randbelow(self.q - 1) + 1

    def is_element(self, v: int, allow_identity: bool = False) -> bool:
        low = 0 if allow_identity else 1
        return isinstance(v, int) and low < v < self.p and pow(v, self.q, self.p) == 1

    def require_element(self, v: int, what: str, allow_identity: bool = False) -> None:
        """allow_identity: 조각이 0이면 y_i·d_i가 1이 될 수 있어 허용."""
        if not self.is_element(v, allow_identity):
            raise VerificationError(f"{what}: 위수 q 부분군의 원소가 아님")


def group() -> Group:
    """[미정] 안전 소수 p=2q+1 (3072비트). 실제 p·g 값이 정해지지 않음."""
    raise Unspecified("3072비트 안전 소수 p와 생성원 g 값 미정")


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller–Rabin (군 파라미터 검사용)."""
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# 2) Shamir 비밀분산·라그랑주 보간
# ──────────────────────────────────────────────────────────────────────────────
def poly_eval(coeffs: Sequence[int], x: int, q: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % q
    return acc


def lagrange_at_zero(xi: int, xs: Sequence[int], q: int) -> int:
    """λ_i = Π_{j≠i} x_j (x_j − x_i)^{-1}  (mod q)."""
    num, den = 1, 1
    for xj in xs:
        if xj != xi:
            num = num * xj % q
            den = den * (xj - xi) % q
    return num * pow(den, -1, q) % q


def assign_numbers(member_ids: Sequence[str], grp: Group) -> dict[str, int]:
    """[미정] 번호는 q보다 작은 서로 다른 값. 배정 규칙은 없음."""
    raise Unspecified("참여자 번호 배정 규칙 미정 (배포자가 직접 지정해야 함)")


# ──────────────────────────────────────────────────────────────────────────────
# 3) 공개 정보 / 서버
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class MemberPublic:
    member_id: str
    x: int                  # 번호
    y: int                  # 검증 공개키 g^{s_i}


@dataclass(frozen=True)
class TeamPublic:
    team_id: str
    key_version: str
    Y: int
    members: dict[str, MemberPublic]

    def validate(self) -> None:
        grp, n = group(), len(self.members)
        if n != N_MEMBERS:
            raise VerificationError(f"참여자는 {N_MEMBERS}명")
        xs = [m.x for m in self.members.values()]
        if len(set(xs)) != n or not all(0 < x < grp.q for x in xs):
            raise VerificationError("참여자 번호는 q보다 작은 서로 다른 값(0 제외)이어야 함")
        grp.require_element(self.Y, "팀 공개키 Y")
        for m in self.members.values():
            grp.require_element(m.y, f"검증 공개키 y_{m.member_id}", allow_identity=True)


@dataclass(frozen=True)
class DocumentRecord:
    doc_id: str
    version: str
    key_version: str
    author_id: str
    C1: int
    salt: bytes
    info: tuple[str, str]   # (문서 ID, 버전)
    iv: bytes
    ciphertext: bytes
    tag: bytes = b""


@dataclass(frozen=True)
class OpenRequest:
    """협력자에게 보내는 공개 요청. 블라인딩 값 t는 들어 있지 않음."""
    request_no: int
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
    """공개 정보와 암호문만 보관. 조각·k·Z·t는 다루지 않음."""
    teams: dict[str, TeamPublic] = field(default_factory=dict)
    documents: dict[str, list[DocumentRecord]] = field(default_factory=dict)

    def register_team(self, team: TeamPublic) -> None:
        team.validate()
        self.teams[team.team_id] = team

    def team(self, team_id: str) -> TeamPublic:
        return self.teams[team_id]

    def store(self, rec: DocumentRecord) -> None:
        group().require_element(rec.C1, "C1")
        self.documents.setdefault(rec.doc_id, []).append(rec)

    def latest(self, doc_id: str) -> DocumentRecord:
        return self.documents[doc_id][-1]


# ──────────────────────────────────────────────────────────────────────────────
# 4) RSA-OAEP 조각 전달
# ──────────────────────────────────────────────────────────────────────────────
def rsa_keypair():
    """[미정] RSA 키 크기."""
    raise Unspecified("RSA 키 크기 미정")


def seal_share(recipient_public_key, x: int, share: int) -> bytes:
    """RSA-OAEP(PK_수신자, (x, s_i)). [미정] OAEP 해시, (번호, 조각) 인코딩, 공개키 인증 방법."""
    raise Unspecified("RSA-OAEP 해시 / (번호, 조각) 인코딩 미정")


def open_share(private_key, sealed: bytes) -> tuple[int, int]:
    raise Unspecified("RSA-OAEP 해시 / (번호, 조각) 인코딩 미정")


# ──────────────────────────────────────────────────────────────────────────────
# 5) 본문 블록 암호 (128비트, 12라운드, 라운드 키 13개)
# ──────────────────────────────────────────────────────────────────────────────
def to_nibbles(v: int) -> list[int]:
    return [(v >> (4 * (BLOCK_NIBBLES - 1 - i))) & 0xF for i in range(BLOCK_NIBBLES)]


def from_nibbles(ns: Sequence[int]) -> int:
    v = 0
    for d in ns:
        v = (v << 4) | d
    return v


def perm_multiplier(round_key: int) -> int:
    """라운드 키 첫 칸이 짝수면 m=3, 홀수면 m=5."""
    return 3 if (round_key >> (4 * (BLOCK_NIBBLES - 1))) % 2 == 0 else 5


def permute(ns: list[int], m: int) -> list[int]:
    n = len(ns)
    return [ns[(m * j) % n] for j in range(n)]          # S'[j] = S[(m·j) mod n]


def inv_permute(ns: list[int], m: int) -> list[int]:
    n = len(ns)
    out = [0] * n
    for j in range(n):
        out[(m * j) % n] = ns[j]
    return out


def diffuse(ns: list[int]) -> list[int]:
    out = []
    for i in range(0, len(ns), 4):                      # 4칸씩 (a, b, c, d)
        a, b, c, d = ns[i:i + 4]
        out += [a ^ b, b ^ c, c ^ d, d ^ a ^ b]
    return out


def inv_diffuse(ns: list[int]) -> list[int]:
    out = []
    for i in range(0, len(ns), 4):                      # d, c, b, a 순서로 되풂
        p, q, s1, s2 = ns[i:i + 4]
        d = s2 ^ p
        c = s1 ^ d
        b = q ^ c
        a = p ^ b
        out += [a, b, c, d]
    return out


def _check_round_keys(round_keys: Sequence[int]) -> None:
    if len(round_keys) != ROUND_KEY_COUNT or not all(0 <= k < 1 << BLOCK_BITS for k in round_keys):
        raise ValueError(f"{BLOCK_BITS}비트 라운드 키 {ROUND_KEY_COUNT}개가 필요함")


def spn_encrypt(block: int, round_keys: Sequence[int]) -> int:
    """round_keys = [RK_1 … RK_12, RK_final]. 마지막 라운드는 확산 생략 후 최종 키 XOR."""
    _check_round_keys(round_keys)
    state = block
    for r in range(ROUNDS):
        rk = round_keys[r]
        ns = [SBOX[v] for v in to_nibbles(state ^ rk)]
        ns = permute(ns, perm_multiplier(rk))
        if r < ROUNDS - 1:
            ns = diffuse(ns)
        state = from_nibbles(ns)
    return state ^ round_keys[-1]


def spn_decrypt(block: int, round_keys: Sequence[int]) -> int:
    _check_round_keys(round_keys)
    state = block ^ round_keys[-1]
    for r in range(ROUNDS - 1, -1, -1):
        rk = round_keys[r]
        ns = to_nibbles(state)
        if r < ROUNDS - 1:
            ns = inv_diffuse(ns)
        ns = inv_permute(ns, perm_multiplier(rk))
        state = from_nibbles([INV_SBOX[v] for v in ns]) ^ rk
    return state


def cbc_encrypt(data: bytes, iv: bytes, round_keys: Sequence[int]) -> bytes:
    if len(iv) != BLOCK_BYTES or len(data) % BLOCK_BYTES:
        raise ValueError(f"IV는 {BLOCK_BYTES}바이트, 데이터는 {BLOCK_BYTES}바이트 배수여야 함")
    prev, out = int.from_bytes(iv, "big"), bytearray()
    for i in range(0, len(data), BLOCK_BYTES):
        prev = spn_encrypt(int.from_bytes(data[i:i + BLOCK_BYTES], "big") ^ prev, round_keys)
        out += prev.to_bytes(BLOCK_BYTES, "big")
    return bytes(out)


def cbc_decrypt(data: bytes, iv: bytes, round_keys: Sequence[int]) -> bytes:
    if len(iv) != BLOCK_BYTES or len(data) % BLOCK_BYTES:
        raise ValueError(f"IV는 {BLOCK_BYTES}바이트, 데이터는 {BLOCK_BYTES}바이트 배수여야 함")
    prev, out = int.from_bytes(iv, "big"), bytearray()
    for i in range(0, len(data), BLOCK_BYTES):
        c = int.from_bytes(data[i:i + BLOCK_BYTES], "big")
        out += (spn_decrypt(c, round_keys) ^ prev).to_bytes(BLOCK_BYTES, "big")
        prev = c
    return bytes(out)


# ──────────────────────────────────────────────────────────────────────────────
# 6) [미정] salt·키 유도·패딩·IV·MAC·증명
# ──────────────────────────────────────────────────────────────────────────────
def new_salt() -> bytes:
    """[미정] salt는 서버에 저장. 길이·생성 방법 없음."""
    raise Unspecified("salt 길이·생성 방법 미정")


def derive_keys(z: int, salt: bytes, doc_id: str, version: str) -> list[int]:
    """Z → HKDF-SHA256(salt, info=문서 ID·버전) → 라운드 키 13개. [미정] 입력 인코딩, 확장 방법."""
    raise Unspecified("HKDF 입력 인코딩 / 라운드 키 13개 확장 규칙 미정")


def pad(data: bytes) -> bytes:
    raise Unspecified("CBC 패딩 방식 미정")


def unpad(data: bytes) -> bytes:
    raise Unspecified("CBC 패딩 방식 미정")


def new_iv() -> bytes:
    raise Unspecified("CBC IV 생성·저장 방식 미정")


def mac_tag(z: int, team: TeamPublic, rec_without_tag: DocumentRecord) -> bytes:
    raise Unspecified("HMAC 해시·키 유도·적용 범위·입력 형식 미정")


def mac_verify(z: int, team: TeamPublic, rec: DocumentRecord) -> None:
    raise Unspecified("HMAC 해시·키 유도·적용 범위·입력 형식 미정")


def make_proof(team: TeamPublic, b_req: int, share: int, d_i: int) -> object:
    raise Unspecified("부분 복호 증명(Chaum–Pedersen) 미구현")


def verify_partial(team: TeamPublic, b_req: int, member: MemberPublic, d_i: int, proof: object) -> None:
    raise Unspecified("부분 복호 증명(Chaum–Pedersen) 미구현")


# ──────────────────────────────────────────────────────────────────────────────
# 7) 결합 (공개값만 다루는 계산)
# ──────────────────────────────────────────────────────────────────────────────
def select_partials(team: TeamPublic, requester_id: str, requester_has_share: bool,
                    responses: Sequence[PartialDecryption]) -> list[PartialDecryption]:
    """정확히 τ명, 요청자가 조각을 가졌다면 자신의 값 포함."""
    grp = group()
    seen, chosen = set(), []
    for r in responses:
        if r.member_id in seen or r.member_id not in team.members:
            continue
        grp.require_element(r.d, f"d_{r.member_id}", allow_identity=True)
        seen.add(r.member_id)
        chosen.append(r)
    if requester_has_share and requester_id not in seen:
        raise VerificationError("요청자가 조각을 가졌다면 자신의 부분 복호값을 포함해야 함")
    if len(chosen) < THRESHOLD:
        raise PermissionError(f"응답 {len(chosen)}명: {THRESHOLD}명 미만이라 복호 거부")
    if len(chosen) > THRESHOLD:
        raise Unspecified(f"{THRESHOLD}명보다 많이 응답했을 때 결합할 {THRESHOLD}명 선택 기준 미정")
    return chosen


def combine(team: TeamPublic, partials: Sequence[PartialDecryption]) -> int:
    """S* = Π d_i^{λ_i}  (mod p)."""
    grp = group()
    ids = [p.member_id for p in partials]
    if len(set(ids)) != THRESHOLD or len(ids) != THRESHOLD:
        raise PermissionError(f"정확히 {THRESHOLD}명의 서로 다른 값이 필요함")
    xs = [team.members[i].x for i in ids]
    s_star = 1
    for p, xi in zip(partials, xs):
        s_star = s_star * pow(p.d, lagrange_at_zero(xi, xs, grp.q), grp.p) % grp.p
    return s_star


# ──────────────────────────────────────────────────────────────────────────────
# 8) 참여자: 모든 역할
# ──────────────────────────────────────────────────────────────────────────────
_request_numbers = count(1)


class Member:
    def __init__(self, member_id: str):
        self.member_id = member_id
        self._share: int | None = None                     # 내 조각 s_i
        self._team_id: str | None = None
        self._open: dict[int, tuple[DocumentRecord, int]] = {}   # 요청 번호 → (문서, 블라인딩 t)

    @property
    def has_share(self) -> bool:
        return self._share is not None

    # ── 배포자 ──────────────────────────────────────────────────────────────
    def deal(self, team_id: str, key_version: str, numbers: dict[str, int],
             recipient_public_keys: dict[str, object]) -> tuple[TeamPublic, dict[str, bytes]]:
        """팀 비밀 s와 계수를 만들고 조각을 나눔.

        numbers               : 참여자 ID → 번호 (배포자가 지정, 배정 규칙은 미정). 배포자 본인 포함.
        recipient_public_keys : 다른 참여자들의 RSA 공개키 (인증 방법은 미정)
        반환                  : (서버에 등록할 공개 정보, 다른 참여자별 봉인된 조각)
        배포자 자신의 조각은 이 객체에 바로 보관하고, s·계수는 함수가 끝나면 버림.
        """
        grp = group()
        if self.member_id not in numbers:
            raise ValueError("배포자도 참여자 번호가 있어야 함")
        if len(numbers) != N_MEMBERS:
            raise ValueError(f"참여자는 {N_MEMBERS}명")
        xs = list(numbers.values())
        if len(set(xs)) != len(xs) or not all(0 < x < grp.q for x in xs):
            raise ValueError("참여자 번호는 q보다 작은 서로 다른 값(0 제외)이어야 함")
        others = [mid for mid in numbers if mid != self.member_id]
        if set(recipient_public_keys) != set(others):
            raise ValueError("배포자를 뺀 모든 참여자의 공개키가 필요함")

        coeffs = [grp.rand_scalar()] + [secrets.randbelow(grp.q) for _ in range(THRESHOLD - 1)]
        Y = pow(grp.g, coeffs[0], grp.p)
        shares = {mid: poly_eval(coeffs, x, grp.q) for mid, x in numbers.items()}
        coeffs.clear()
        team = TeamPublic(team_id, key_version, Y,
                          {mid: MemberPublic(mid, numbers[mid], pow(grp.g, s, grp.p)) for mid, s in shares.items()})
        team.validate()

        sealed = {mid: seal_share(recipient_public_keys[mid], numbers[mid], shares[mid]) for mid in others}
        self._share, self._team_id = shares[self.member_id], team_id
        shares.clear()
        return team, sealed

    # ── 수신자 ──────────────────────────────────────────────────────────────
    def receive_share(self, team: TeamPublic, private_key, sealed: bytes) -> None:
        """봉인된 (번호, 조각)을 열어 등록 정보와 맞는지 확인 후 보관."""
        x, s_i = open_share(private_key, sealed)
        grp, me = group(), team.members[self.member_id]
        if x != me.x or not 0 <= s_i < grp.q or pow(grp.g, s_i, grp.p) != me.y:
            raise VerificationError("받은 (번호, 조각)이 등록된 공개 정보와 맞지 않음")
        self._share, self._team_id = s_i, team.team_id

    # ── 작성자 ──────────────────────────────────────────────────────────────
    def write_document(self, team: TeamPublic, doc_id: str, version: str, plaintext: bytes) -> DocumentRecord:
        """k와 Z는 이 메서드 밖으로 나가지 않음. 반환된 레코드를 서버에 저장."""
        grp = group()
        team.validate()
        k = grp.rand_scalar()
        C1, Z = pow(grp.g, k, grp.p), pow(team.Y, k, grp.p)
        del k
        salt = new_salt()
        round_keys = derive_keys(Z, salt, doc_id, version)
        iv = new_iv()
        ct = cbc_encrypt(pad(plaintext), iv, round_keys)
        rec = DocumentRecord(doc_id, version, team.key_version, self.member_id, C1, salt,
                             (doc_id, version), iv, ct)
        return replace(rec, tag=mac_tag(Z, team, rec))

    # ── 요청자 ──────────────────────────────────────────────────────────────
    def begin_open(self, team: TeamPublic, record: DocumentRecord) -> OpenRequest:
        """블라인딩 값 t를 만들어 이 객체에만 보관하고, 협력자에게 보낼 요청을 돌려줌."""
        grp = group()
        if record.key_version != team.key_version:
            raise VerificationError("문서의 키 버전이 팀 키 버전과 다름")
        grp.require_element(record.C1, "C1")
        t = grp.rand_scalar()
        req = OpenRequest(next(_request_numbers), self.member_id, record.doc_id, record.version,
                          record.C1 * pow(grp.g, t, grp.p) % grp.p)
        self._open[req.request_no] = (record, t)
        return req

    def finish_open(self, team: TeamPublic, req: OpenRequest,
                    helper_responses: Sequence[PartialDecryption]) -> bytes:
        """협력자 응답 + 자기 부분 복호값 → 검증 → 결합 → t 제거 → MAC 확인 → 키 유도 → 복호."""
        if req.requester_id != self.member_id or req.request_no not in self._open:
            raise PermissionError("내가 만든 요청이 아님")
        record, t = self._open.pop(req.request_no)
        responses = list(helper_responses)
        if self.has_share:
            responses.insert(0, self.respond(team, req))
        chosen = select_partials(team, self.member_id, self.has_share, responses)
        for p in chosen:
            verify_partial(team, req.b_req, team.members[p.member_id], p.d, p.proof)
        p_ = group().p
        z = combine(team, chosen) * pow(pow(team.Y, t, p_), -1, p_) % p_
        del t
        mac_verify(z, team, record)
        round_keys = derive_keys(z, record.salt, record.doc_id, record.version)
        return unpad(cbc_decrypt(record.ciphertext, record.iv, round_keys))

    def open_document(self, team: TeamPublic, record: DocumentRecord,
                      helpers: Sequence["Member"]) -> bytes:
        """요청 → 협력자 응답 수집 → 복원을 한 번에."""
        req = self.begin_open(team, record)
        try:
            return self.finish_open(team, req, [h.respond(team, req) for h in helpers if h is not self])
        finally:
            self._open.pop(req.request_no, None)

    # ── 협력자 ──────────────────────────────────────────────────────────────
    def respond(self, team: TeamPublic, req: OpenRequest) -> PartialDecryption:
        """요청값 B에 자기 조각을 적용. B만 보며 C1·t·Z는 모름."""
        if self._share is None or self._team_id != team.team_id:
            raise PermissionError("이 팀의 조각이 없음")
        grp = group()
        grp.require_element(req.b_req, "B_req")
        d = pow(req.b_req, self._share, grp.p)
        return PartialDecryption(self.member_id, d, make_proof(team, req.b_req, self._share, d))


# ──────────────────────────────────────────────────────────────────────────────
# 9) 자체 시험
# ──────────────────────────────────────────────────────────────────────────────
def _raises(exc: type[BaseException], f) -> None:
    try:
        f()
    except exc:
        return
    raise AssertionError(f"{exc.__name__}가 발생하지 않음")


def self_test() -> None:
    for f in (group, lambda: assign_numbers([], None), rsa_keypair, lambda: seal_share(None, 0, 0),
              new_salt, lambda: derive_keys(0, b"", "", ""), lambda: pad(b""), new_iv):
        _raises(Unspecified, f)

    a = Member("A")
    _raises(Unspecified, lambda: a.deal("team", "k1", {}, {}))
    _raises(Unspecified, lambda: a.write_document(None, "doc", "v1", b""))
    _raises(Unspecified, lambda: a.begin_open(None, None))
    _raises(PermissionError, lambda: a.respond(None, OpenRequest(0, "B", "doc", "v1", 2)))
    _raises(PermissionError, lambda: a.finish_open(None, OpenRequest(0, "B", "doc", "v1", 2), []))

    rks = [secrets.randbits(BLOCK_BITS) for _ in range(ROUND_KEY_COUNT)]
    for _ in range(200):
        b = secrets.randbits(BLOCK_BITS)
        assert spn_decrypt(spn_encrypt(b, rks), rks) == b
    data, iv = secrets.token_bytes(BLOCK_BYTES * 4), secrets.token_bytes(BLOCK_BYTES)
    assert cbc_decrypt(cbc_encrypt(data, iv, rks), iv, rks) == data

    print("자체 시험 통과")


if __name__ == "__main__":
    self_test()
