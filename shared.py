"""StarPath 공통 요소: 진행 출력, 상수, 군, 블록 규격, HKDF, MAC, 문서 레코드

키 생성(keygen.py) · 암호화(encrypt.py) · 복호화(decrypt.py)가 함께 쓰는 부분만 둔다.

진행 출력
  - set_trace(0): 끔, set_trace(1): 초기 설정·암호화·복호화 단계별 값, set_trace(2): 블록 암호 라운드까지
  - [비밀] 표시 값(s, 계수, k, t, 조각)은 과정을 보여 주기 위한 출력이며 실제 운용에서는 끄고 사용
  - capture(): 출력을 화면 대신 목록에 모음 (웹 시연에서 참여자별 화면에 보여 줄 때 사용)
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence

TRACE_LEVEL = 1
_sink: Callable[[str], None] = print


def set_trace(level: int) -> None:
    global TRACE_LEVEL
    TRACE_LEVEL = level


def say(level: int, msg: str) -> None:
    if TRACE_LEVEL >= level:
        _sink(msg)


@contextlib.contextmanager
def capture() -> Iterator[list[str]]:
    """with 블록 안의 진행 출력을 목록으로 모음"""
    global _sink
    lines: list[str] = []
    prev, _sink = _sink, lines.append
    try:
        yield lines
    finally:
        _sink = prev


def show(v) -> str:
    """작은 수는 그대로, 큰 수·긴 바이트는 앞뒤만 보여 줌"""
    if isinstance(v, (bytes, bytearray)):
        h = bytes(v).hex().upper()
        return h if len(h) <= 40 else f"{h[:16]}…{h[-16:]} ({len(v)}바이트)"
    if isinstance(v, int) and not isinstance(v, bool):
        if v.bit_length() <= 64:
            return str(v)
        h = f"{v:X}"
        return f"0x{h[:12]}…{h[-12:]} ({v.bit_length()}비트)"
    return str(v)


def hexw(v: int, nibbles: int) -> str:
    return f"{v:0{nibbles}X}"


N_MEMBERS, THRESHOLD = 5, 3

def _aes_sbox() -> list[int]:
    """AES S-Box (FIPS 197): GF(2^8) 역원 → 아핀 변환 (x⁸+x⁴+x³+x+1, 상수 0x63)"""
    def mul(a: int, b: int) -> int:
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r

    def inv(a: int) -> int:
        r, e = 1, 254
        while e:
            if e & 1:
                r = mul(r, a)
            a, e = mul(a, a), e >> 1
        return r

    table = []
    for x in range(256):
        b = inv(x) if x else 0
        y = b
        for i in range(1, 5):
            y ^= ((b << i) | (b >> (8 - i))) & 0xFF
        table.append(y ^ 0x63)
    return table


SBOX = _aes_sbox()
INV_SBOX = [SBOX.index(i) for i in range(256)]
assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xED and SBOX[0xFF] == 0x16


def sub_bytes(v: int, n_bytes: int, table: Sequence[int] = SBOX) -> int:
    """블록을 바이트로 나눠 S-Box 표로 치환"""
    return int.from_bytes(bytes(table[b] for b in v.to_bytes(n_bytes, "big")), "big")

MAC_HASH = "sha256"
SALT_BYTES = 32
ENC_KEY_BYTES = 32


class VerificationError(ValueError):
    """입력값·조각·응답 검증 실패"""


def encode_fields(*parts: bytes | str | int) -> bytes:
    out = bytearray()
    for p in parts:
        if isinstance(p, str):
            b = b"s" + p.encode("utf-8")
        elif isinstance(p, int) and not isinstance(p, bool) and p >= 0:
            b = b"i" + p.to_bytes((p.bit_length() + 7) // 8 or 1, "big")
        elif isinstance(p, (bytes, bytearray)):
            b = b"b" + bytes(p)
        else:
            raise TypeError(f"인코딩할 수 없는 값: {p!r}")
        out += len(b).to_bytes(4, "big") + b
    return bytes(out)


_checked_groups: set = set()


@dataclass(frozen=True)
class Group:
    """안전 소수 p = 2q+1, g는 위수 q 부분군의 원소"""
    p: int
    q: int
    g: int

    @property
    def elem_bytes(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def check(self) -> None:
        if self in _checked_groups:
            return
        if self.p != 2 * self.q + 1:
            raise VerificationError("p = 2q + 1 이 아님")
        if not (is_probable_prime(self.p) and is_probable_prime(self.q)):
            raise VerificationError("p 또는 q가 소수가 아님")
        if self.g in (0, 1) or pow(self.g, self.q, self.p) != 1:
            raise VerificationError("g가 위수 q 부분군에 있지 않음")
        _checked_groups.add(self)

    def rand_scalar(self) -> int:
        """1 … q-1 범위의 균등 난수"""
        return secrets.randbelow(self.q - 1) + 1

    def is_element(self, v: int, allow_identity: bool = False) -> bool:
        low = 0 if allow_identity else 1
        return isinstance(v, int) and low < v < self.p and pow(v, self.q, self.p) == 1

    def require_element(self, v: int, what: str, allow_identity: bool = False) -> None:
        """allow_identity: 조각이 0이면 y_i·d_i가 1이 될 수 있어 허용"""
        if not self.is_element(v, allow_identity):
            raise VerificationError(f"{what}: 위수 q 부분군의 원소가 아님")


_P3072 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
REAL_GROUP = Group(p=_P3072, q=(_P3072 - 1) // 2, g=2)


def group() -> Group:
    return REAL_GROUP


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller–Rabin (군 파라미터 검사용)"""
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


@dataclass(frozen=True)
class BlockSpec:
    block_bytes: int
    rounds: int

    @property
    def nibbles(self) -> int:
        return self.block_bytes * 2

    @property
    def bits(self) -> int:
        return self.block_bytes * 8

    @property
    def round_key_count(self) -> int:
        return self.rounds + 1


REAL_BLOCK = BlockSpec(block_bytes=16, rounds=12)
KNOWN_BLOCKS = (REAL_BLOCK,)


def to_nibbles(v: int, n: int) -> list[int]:
    return [(v >> (4 * (n - 1 - i))) & 0xF for i in range(n)]


def from_nibbles(ns: Sequence[int]) -> int:
    v = 0
    for d in ns:
        v = (v << 4) | d
    return v


def perm_multiplier(round_key: int, n: int) -> int:
    """라운드 키 첫 칸이 짝수면 m=3, 홀수면 m=5"""
    # [직접 설계] 라운드 키 첫 칸으로 재배열 배수 m 선택
    return 3 if (round_key >> (4 * (n - 1))) % 2 == 0 else 5


def check_block(block: int, round_keys: Sequence[int], spec: BlockSpec) -> None:
    if not 0 <= block < 1 << spec.bits:
        raise ValueError(f"블록은 {spec.bits}비트여야 함")
    if len(round_keys) != spec.round_key_count or not all(0 <= k < 1 << spec.bits for k in round_keys):
        raise ValueError(f"{spec.bits}비트 라운드 키 {spec.round_key_count}개가 필요함")


_SHA256_LEN = 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * _SHA256_LEN, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not 0 < length <= 255 * _SHA256_LEN:
        raise ValueError("HKDF 출력 길이 범위 초과")
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def derive_keys(z: int, grp: Group, salt: bytes, doc_id: str, key_version: str,
                spec: BlockSpec = REAL_BLOCK) -> list[int]:
    """Z → HKDF-SHA256(salt, info=(문서 ID, 키 버전)) → 암호화 키 → HKDF → 라운드 키"""
    k_enc = hkdf(z.to_bytes(grp.elem_bytes, "big"), salt, encode_fields(doc_id, key_version), ENC_KEY_BYTES)
    bb, cnt = spec.block_bytes, spec.round_key_count
    rk = hkdf(k_enc, b"", b"StarPath round keys", bb * cnt)
    keys = [int.from_bytes(rk[i * bb:(i + 1) * bb], "big") for i in range(cnt)]
    say(1, f"    HKDF-SHA256(Z, salt, info=({doc_id}, {key_version})) → 암호화 키 {show(k_enc)}")
    names = [f"RK{i + 1}" for i in range(cnt - 1)] + ["RK_f"]
    items = [f"{nm}={hexw(k, spec.nibbles)}" for nm, k in zip(names, keys)]
    per_line = 3 if spec.nibbles > 8 else cnt
    for i in range(0, cnt, per_line):
        say(1, ("    라운드 키 " if i == 0 else "              ") + ", ".join(items[i:i + per_line]))
    return keys


@dataclass(frozen=True)
class DocumentRecord:
    team_id: str
    doc_id: str
    version: str
    key_version: str
    author_id: str
    C1: int
    salt: bytes
    iv: bytes
    block: BlockSpec
    ciphertext: bytes
    tag: bytes = b""

    @property
    def info(self) -> tuple[str, str]:
        return self.doc_id, self.key_version


def hmac_tag(key: bytes, data: bytes, hash_name: str | None = None) -> bytes:
    return hmac.new(key, data, hash_name or MAC_HASH).digest()


def mac_key(z: int, rec: DocumentRecord, grp: Group) -> bytes:
    return hkdf(z.to_bytes(grp.elem_bytes, "big"), rec.salt,
                encode_fields(rec.doc_id, rec.key_version, "mac"), ENC_KEY_BYTES)


def mac_input(rec: DocumentRecord) -> bytes:
    return encode_fields(rec.team_id, rec.doc_id, rec.version, rec.key_version, rec.author_id, rec.C1,
                         rec.salt, rec.iv, rec.block.block_bytes, rec.block.rounds, rec.ciphertext)
