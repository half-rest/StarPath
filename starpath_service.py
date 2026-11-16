"""

[미정] 보고서에 정의되지 않은 부분 (값은 미정, 동작을 위해 임시값을 넣어 둠)
  1. group("real")          : RFC 3526 3072비트 MODP 군 (안전 소수 p, g=2)
  2. assign_numbers()       : 넘겨받은 순서대로 1, 2, …, N
  3. RSA_KEY_BITS=4096 / RSA_PUBLIC_EXPONENT=65537 / OAEP_HASH·MGF1_HASH=SHA-256
     encode_share()         : (번호, 조각)을 각각 2바이트 길이 + 빅엔디언 정수로 이어 붙임
  4. new_salt()             : 32바이트 난수
  5. derive_keys()          : Z는 p 길이 빅엔디언, info=encode_fields(문서 ID, 키 버전),
                              암호화 키 32바이트 → HKDF로 라운드 키 (R+1)개
  6. pad() / unpad()        : PKCS#7
  7. new_iv()               : 블록 크기 난수
  8. MAC_HASH=sha256 / mac_key() / mac_input() : Z에서 HKDF로 MAC 키, 태그 외 모든 레코드 필드
  9. make_proof() / verify_partial() : Chaum–Pedersen (Fiat–Shamir, SHA-256)
 10. pick_threshold()       : 요청자 먼저, 나머지는 응답 순서로 τ명
 11. authenticate()         : 신원 확인 없이 통과 (보안 기능 없음)
 12. encode_fields()        : 필드마다 4바이트 길이 + 형식 태그 + 값

[미정] 표시 방법
  - 함수: @provisional("…") 데코레이터, 상수: provisional_value(…)
  - 모두 PROVISIONAL 사전에 등록되고, 처음 사용할 때 ProvisionalWarning이 한 번 출력됨

진행 출력
  - set_trace(0): 끔, set_trace(1): 초기 설정·암호화·복호화 단계별 값, set_trace(2): 블록 암호 라운드까지
  - [비밀] 표시 값(s, 계수, k, t, 조각)은 과정을 보여 주기 위한 출력이며 실제 운용에서는 끄고 사용
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import secrets
import warnings
from dataclasses import dataclass, field, replace
from itertools import count
from typing import Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ──────────────────────────────────────────────────────────────────────────────
# 진행 출력
# ──────────────────────────────────────────────────────────────────────────────
TRACE_LEVEL = 1


def set_trace(level: int) -> None:
    global TRACE_LEVEL
    TRACE_LEVEL = level


def say(level: int, msg: str) -> None:
    if TRACE_LEVEL >= level:
        print(msg)


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


# ──────────────────────────────────────────────────────────────────────────────
# [미정] 표시 장치
# ──────────────────────────────────────────────────────────────────────────────
PROVISIONAL: dict[str, str] = {}
_warned: set[str] = set()


class ProvisionalWarning(UserWarning):
    """보고서에 정의되지 않은 값(임시값)이 사용됨"""


def _warn_provisional(name: str) -> None:
    if name not in _warned:
        _warned.add(name)
        warnings.warn(f"[미정] {name}: {PROVISIONAL[name]}", ProvisionalWarning, stacklevel=3)


def provisional(description: str):
    """보고서에 근거가 없는 함수 표시"""
    def deco(func):
        PROVISIONAL[func.__name__] = description

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _warn_provisional(func.__name__)
            return func(*args, **kwargs)

        wrapper.provisional = description
        return wrapper
    return deco


def provisional_value(name: str, value, description: str):
    """보고서에 근거가 없는 상수 표시"""
    PROVISIONAL[name] = description
    return value


# ──────────────────────────────────────────────────────────────────────────────
# 0) 상수
# ──────────────────────────────────────────────────────────────────────────────
N_MEMBERS, THRESHOLD = 5, 3

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
INV_SBOX = [SBOX.index(i) for i in range(16)]

RSA_KEY_BITS: int = provisional_value(
    "RSA_KEY_BITS", 4096, "RSA 4096비트 (3072비트 군의 조각이 OAEP 한 블록에 들어가는 크기)")
RSA_PUBLIC_EXPONENT: int = provisional_value(
    "RSA_PUBLIC_EXPONENT", 65537, "RSA 공개 지수 65537")
OAEP_HASH: hashes.HashAlgorithm = provisional_value("OAEP_HASH", hashes.SHA256(), "OAEP 해시 SHA-256")
MGF1_HASH: hashes.HashAlgorithm = provisional_value("MGF1_HASH", hashes.SHA256(), "MGF1 해시 SHA-256")
MAC_HASH: str = provisional_value("MAC_HASH", "sha256", "HMAC 해시 SHA-256")
SALT_BYTES: int = provisional_value("SALT_BYTES", 32, "salt 32바이트")
ENC_KEY_BYTES: int = provisional_value("ENC_KEY_BYTES", 32, "HKDF 암호화 키·MAC 키 32바이트")


class VerificationError(ValueError):
    """입력값·조각·응답 검증 실패"""


@provisional("필드마다 4바이트 길이 + 형식 태그(s/i/b) + 값(UTF-8 / 빅엔디언 / 바이트)")
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


# ──────────────────────────────────────────────────────────────────────────────
# 1) 군
# ──────────────────────────────────────────────────────────────────────────────
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


@provisional("실제 군 = RFC 3526 3072비트 MODP 군 (안전 소수 p, g=2)")
def _real_group() -> Group:
    return REAL_GROUP


def group() -> Group:
    return _real_group()


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


# ──────────────────────────────────────────────────────────────────────────────
# 2) Shamir 비밀분산·라그랑주 보간·블라인딩
# ──────────────────────────────────────────────────────────────────────────────
def poly_eval(coeffs: Sequence[int], x: int, q: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % q
    return acc


def lagrange_at_zero(xi: int, xs: Sequence[int], q: int) -> int:
    """λ_i = Π_{j≠i} x_j (x_j − x_i)^{-1}  (mod q)"""
    num, den = 1, 1
    for xj in xs:
        if xj != xi:
            num = num * xj % q
            den = den * (xj - xi) % q
    return num * pow(den, -1, q) % q


@provisional("참여자 번호 = 넘겨받은 순서대로 1, 2, …, N")
def assign_numbers(member_ids: Sequence[str], grp: Group) -> dict[str, int]:
    if len(set(member_ids)) != len(member_ids):
        raise ValueError("참여자 ID가 중복됨")
    if len(member_ids) >= grp.q:
        raise ValueError("참여자 수가 q 이상")
    return {mid: i + 1 for i, mid in enumerate(member_ids)}


def check_numbers(numbers: dict[str, int], grp: Group) -> None:
    xs = list(numbers.values())
    if len(numbers) != N_MEMBERS:
        raise VerificationError(f"참여자는 {N_MEMBERS}명")
    if len(set(xs)) != len(xs) or not all(isinstance(x, int) and 0 < x < grp.q for x in xs):
        raise VerificationError("참여자 번호는 q보다 작은 서로 다른 값(0 제외)이어야 함")


def make_shares(coeffs: Sequence[int], numbers: dict[str, int], q: int) -> dict[str, int]:
    return {mid: poly_eval(coeffs, x, q) for mid, x in numbers.items()}


def encapsulate(grp: Group, Y: int, k: int) -> tuple[int, int]:
    """C1 = g^k, Z = Y^k"""
    return pow(grp.g, k, grp.p), pow(Y, k, grp.p)


def blind(grp: Group, C1: int, t: int) -> int:
    """B = C1 · g^t"""
    return C1 * pow(grp.g, t, grp.p) % grp.p


def partial_decrypt(grp: Group, b: int, share: int) -> int:
    """d_i = B^{s_i}"""
    return pow(b, share, grp.p)


def combine(grp: Group, points: Sequence[tuple[int, int]]) -> int:
    """S* = Π d_i^{λ_i}  (mod p)"""
    xs = [x for x, _ in points]
    if len(points) != THRESHOLD or len(set(xs)) != THRESHOLD:
        raise PermissionError(f"정확히 {THRESHOLD}명의 서로 다른 값이 필요함")
    s_star = 1
    for x, d in points:
        s_star = s_star * pow(d, lagrange_at_zero(x, xs, grp.q), grp.p) % grp.p
    return s_star


def unblind(grp: Group, s_star: int, Y: int, t: int) -> int:
    """Z' = S* · (Y^t)^{-1}"""
    return s_star * pow(pow(Y, t, grp.p), -1, grp.p) % grp.p


# ──────────────────────────────────────────────────────────────────────────────
# 3) 본문 블록 암호 (128비트·12라운드)
# ──────────────────────────────────────────────────────────────────────────────
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
    return 3 if (round_key >> (4 * (n - 1))) % 2 == 0 else 5


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


def _check_block(block: int, round_keys: Sequence[int], spec: BlockSpec) -> None:
    if not 0 <= block < 1 << spec.bits:
        raise ValueError(f"블록은 {spec.bits}비트여야 함")
    if len(round_keys) != spec.round_key_count or not all(0 <= k < 1 << spec.bits for k in round_keys):
        raise ValueError(f"{spec.bits}비트 라운드 키 {spec.round_key_count}개가 필요함")


def spn_encrypt(block: int, round_keys: Sequence[int], spec: BlockSpec = REAL_BLOCK) -> int:
    """round_keys = [RK_1 … RK_R, RK_final]. 마지막 라운드는 확산 생략 후 최종 키 XOR"""
    _check_block(block, round_keys, spec)
    n, state = spec.nibbles, block
    for r in range(spec.rounds):
        rk = round_keys[r]
        x = state ^ rk
        ns = [SBOX[v] for v in to_nibbles(x, n)]
        sb = from_nibbles(ns)
        m = perm_multiplier(rk, n)
        ns = permute(ns, m)
        pm = from_nibbles(ns)
        if r < spec.rounds - 1:
            ns = diffuse(ns)
        state = from_nibbles(ns)
        say(2, f"        R{r + 1}: ⊕RK {hexw(x, n)} → S-Box {hexw(sb, n)} → 재배열(m={m}) {hexw(pm, n)}"
               + (f" → 확산 {hexw(state, n)}" if r < spec.rounds - 1 else " (확산 생략)"))
    out = state ^ round_keys[-1]
    say(2, f"        ⊕RK_f → {hexw(out, n)}")
    return out


def spn_decrypt(block: int, round_keys: Sequence[int], spec: BlockSpec = REAL_BLOCK) -> int:
    _check_block(block, round_keys, spec)
    n, state = spec.nibbles, block ^ round_keys[-1]
    say(2, f"        ⊕RK_f → {hexw(state, n)}")
    for r in range(spec.rounds - 1, -1, -1):
        rk = round_keys[r]
        ns = to_nibbles(state, n)
        if r < spec.rounds - 1:
            ns = inv_diffuse(ns)
        m = perm_multiplier(rk, n)
        ns = inv_permute(ns, m)
        state = from_nibbles([INV_SBOX[v] for v in ns]) ^ rk
        say(2, f"        R{r + 1} 역: " + ("역확산 → " if r < spec.rounds - 1 else "")
               + f"역재배열(m={m}) → 역 S-Box → ⊕RK = {hexw(state, n)}")
    return state


def cbc_encrypt(data: bytes, iv: bytes, round_keys: Sequence[int], spec: BlockSpec = REAL_BLOCK) -> bytes:
    bb = spec.block_bytes
    if len(iv) != bb or len(data) % bb:
        raise ValueError(f"IV는 {bb}바이트, 데이터는 {bb}바이트 배수여야 함")
    prev, out = int.from_bytes(iv, "big"), bytearray()
    for i in range(0, len(data), bb):
        p = int.from_bytes(data[i:i + bb], "big")
        say(2, f"      블록 {i // bb + 1}: P {hexw(p, spec.nibbles)} ⊕ 이전 {hexw(prev, spec.nibbles)}"
               f" = {hexw(p ^ prev, spec.nibbles)}")
        prev = spn_encrypt(p ^ prev, round_keys, spec)
        out += prev.to_bytes(bb, "big")
    return bytes(out)


def cbc_decrypt(data: bytes, iv: bytes, round_keys: Sequence[int], spec: BlockSpec = REAL_BLOCK) -> bytes:
    bb = spec.block_bytes
    if len(iv) != bb or len(data) % bb:
        raise ValueError(f"IV는 {bb}바이트, 데이터는 {bb}바이트 배수여야 함")
    prev, out = int.from_bytes(iv, "big"), bytearray()
    for i in range(0, len(data), bb):
        c = int.from_bytes(data[i:i + bb], "big")
        say(2, f"      블록 {i // bb + 1}: C {hexw(c, spec.nibbles)}")
        p = spn_decrypt(c, round_keys, spec) ^ prev
        say(2, f"        ⊕ 이전 {hexw(prev, spec.nibbles)} → P {hexw(p, spec.nibbles)}")
        out += p.to_bytes(bb, "big")
        prev = c
    return bytes(out)


@provisional("CBC 패딩 = PKCS#7")
def pad(data: bytes, spec: BlockSpec = REAL_BLOCK) -> bytes:
    n = spec.block_bytes - len(data) % spec.block_bytes
    return data + bytes([n]) * n


@provisional("CBC 패딩 = PKCS#7 (MAC 확인 뒤에만 호출)")
def unpad(data: bytes, spec: BlockSpec = REAL_BLOCK) -> bytes:
    if not data or len(data) % spec.block_bytes:
        raise VerificationError("패딩 길이가 잘못됨")
    n = data[-1]
    if not 1 <= n <= spec.block_bytes or data[-n:] != bytes([n]) * n:
        raise VerificationError("패딩이 잘못됨")
    return data[:-n]


@provisional("IV = 블록 크기만큼의 난수, 레코드에 함께 저장")
def new_iv(spec: BlockSpec = REAL_BLOCK) -> bytes:
    return secrets.token_bytes(spec.block_bytes)


# ──────────────────────────────────────────────────────────────────────────────
# 4) HKDF-SHA256 (RFC 5869)
# ──────────────────────────────────────────────────────────────────────────────
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


@provisional("salt = SALT_BYTES 길이의 난수")
def new_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


@provisional("Z → p 길이 빅엔디언, info = encode_fields(문서 ID, 키 버전), 암호화 키 ENC_KEY_BYTES, "
             "라운드 키 = HKDF(암호화 키, salt 없음, info='StarPath round keys')를 블록 크기씩 자름")
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


# ──────────────────────────────────────────────────────────────────────────────
# 5) HMAC
# ──────────────────────────────────────────────────────────────────────────────
def hmac_tag(key: bytes, data: bytes, hash_name: str | None = None) -> bytes:
    return hmac.new(key, data, hash_name or MAC_HASH).digest()


def hmac_verify(key: bytes, data: bytes, tag: bytes, hash_name: str | None = None) -> None:
    if not hmac.compare_digest(hmac_tag(key, data, hash_name), tag):
        raise VerificationError("MAC 불일치: 변조된 암호문")


@provisional("MAC 키 = HKDF(Z, salt, info=encode_fields(문서 ID, 키 버전, 'mac'))")
def mac_key(z: int, rec: "DocumentRecord", grp: Group) -> bytes:
    return hkdf(z.to_bytes(grp.elem_bytes, "big"), rec.salt,
                encode_fields(rec.doc_id, rec.key_version, "mac"), ENC_KEY_BYTES)


@provisional("MAC 적용 범위 = 태그를 뺀 레코드 전체 필드 (encode_fields)")
def mac_input(rec: "DocumentRecord") -> bytes:
    return encode_fields(rec.team_id, rec.doc_id, rec.version, rec.key_version, rec.author_id, rec.C1,
                         rec.salt, rec.iv, rec.block.block_bytes, rec.block.rounds, rec.ciphertext)


# ──────────────────────────────────────────────────────────────────────────────
# 6) RSA-OAEP 조각 전달
# ──────────────────────────────────────────────────────────────────────────────
def rsa_keypair(bits: int | None = None, public_exponent: int | None = None) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=public_exponent or RSA_PUBLIC_EXPONENT,
                                    key_size=bits or RSA_KEY_BITS)


def _oaep(hash_alg: hashes.HashAlgorithm | None, mgf_hash: hashes.HashAlgorithm | None) -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(mgf_hash or MGF1_HASH), algorithm=hash_alg or OAEP_HASH, label=None)


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, payload: bytes,
                     hash_alg: hashes.HashAlgorithm | None = None,
                     mgf_hash: hashes.HashAlgorithm | None = None) -> bytes:
    return public_key.encrypt(payload, _oaep(hash_alg, mgf_hash))


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, sealed: bytes,
                     hash_alg: hashes.HashAlgorithm | None = None,
                     mgf_hash: hashes.HashAlgorithm | None = None) -> bytes:
    try:
        return private_key.decrypt(sealed, _oaep(hash_alg, mgf_hash))
    except ValueError:
        raise VerificationError("봉인된 조각을 열 수 없음") from None


@provisional("(번호, 조각) = 각각 2바이트 길이 + 빅엔디언 정수")
def encode_share(x: int, share: int) -> bytes:
    out = bytearray()
    for v in (x, share):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        out += len(b).to_bytes(2, "big") + b
    return bytes(out)


@provisional("(번호, 조각) = 각각 2바이트 길이 + 빅엔디언 정수")
def decode_share(data: bytes) -> tuple[int, int]:
    vals, i = [], 0
    for _ in range(2):
        if i + 2 > len(data):
            raise VerificationError("봉인된 조각 형식이 잘못됨")
        n = int.from_bytes(data[i:i + 2], "big")
        if i + 2 + n > len(data):
            raise VerificationError("봉인된 조각 형식이 잘못됨")
        vals.append(int.from_bytes(data[i + 2:i + 2 + n], "big"))
        i += 2 + n
    if i != len(data):
        raise VerificationError("봉인된 조각 형식이 잘못됨")
    return vals[0], vals[1]


def seal_share(recipient_public_key: rsa.RSAPublicKey, x: int, share: int) -> bytes:
    """RSA-OAEP(PK_수신자, (x, s_i))"""
    return rsa_oaep_encrypt(recipient_public_key, encode_share(x, share))


def open_share(private_key: rsa.RSAPrivateKey, sealed: bytes) -> tuple[int, int]:
    return decode_share(rsa_oaep_decrypt(private_key, sealed))


# ──────────────────────────────────────────────────────────────────────────────
# 7) 부분 복호 증명·신원 확인
# ──────────────────────────────────────────────────────────────────────────────
def _challenge(grp: Group, *vals: int) -> int:
    return int.from_bytes(hashlib.sha256(encode_fields(grp.p, grp.g, *vals)).digest(), "big") % grp.q


@provisional("Chaum–Pedersen 증명 (Fiat–Shamir, SHA-256): log_g y_i = log_B d_i")
def make_proof(grp: Group, b: int, share: int, d: int) -> tuple[int, int]:
    y = pow(grp.g, share, grp.p)
    w = grp.rand_scalar()
    c = _challenge(grp, y, b, d, pow(grp.g, w, grp.p), pow(b, w, grp.p))
    return c, (w + c * share) % grp.q


@provisional("Chaum–Pedersen 증명 검증 (Fiat–Shamir, SHA-256)")
def verify_partial(grp: Group, b: int, y: int, d: int, proof: object) -> None:
    if not (isinstance(proof, tuple) and len(proof) == 2
            and all(isinstance(v, int) and 0 <= v < grp.q for v in proof)):
        raise VerificationError("증명 형식이 잘못됨")
    c, z = proof
    a1 = pow(grp.g, z, grp.p) * pow(y, -c, grp.p) % grp.p
    a2 = pow(b, z, grp.p) * pow(d, -c, grp.p) % grp.p
    if _challenge(grp, y, b, d, a1, a2) != c:
        raise VerificationError("부분 복호 증명 검증 실패")


@provisional("신원 확인 없이 통과 (보안 기능 없음, 밝힌 ID를 그대로 믿음)")
def authenticate(team: "TeamPublic", member_id: str, message: object) -> None:
    return None


# ──────────────────────────────────────────────────────────────────────────────
# 8) 공개 정보 / 서버
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


# ──────────────────────────────────────────────────────────────────────────────
# 9) 결합
# ──────────────────────────────────────────────────────────────────────────────
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
    if requester_has_share and req.requester_id not in seen:
        raise VerificationError("요청자가 조각을 가졌다면 자신의 부분 복호값을 포함해야 함")
    if len(valid) < THRESHOLD:
        raise PermissionError(f"검증 통과 {len(valid)}명: {THRESHOLD}명 미만이라 복호 거부")
    chosen = pick_threshold(valid, req.requester_id) if len(valid) > THRESHOLD else valid
    say(1, f"  결합 대상 {THRESHOLD}명: {', '.join(p.member_id for p in chosen)}")
    return chosen


# ──────────────────────────────────────────────────────────────────────────────
# 10) 참여자
# ──────────────────────────────────────────────────────────────────────────────
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
        check_numbers(numbers, grp)
        others = [mid for mid in numbers if mid != self.member_id]
        if set(recipient_public_keys) != set(others):
            raise ValueError("배포자를 뺀 모든 참여자의 공개키가 필요함")

        say(1, f"══ 초기 설정 (배포자 {self.member_id}) ══")
        tag = "[미정] " if grp == REAL_GROUP else ""
        say(1, f"  {tag}공개 파라미터 p={show(grp.p)}, q={show(grp.q)}, g={grp.g}, 임계값 {THRESHOLD}-of-{N_MEMBERS}")
        if grp == REAL_GROUP:
            say(1, "    (보고서는 3072비트 안전 소수만 정함 → p·g 값은 미정, RFC 3526 군을 임시로 사용)")
        say(1, "  참여자 번호 " + ", ".join(f"{mid}={x}" for mid, x in numbers.items()))
        coeffs = [grp.rand_scalar()] + [secrets.randbelow(grp.q) for _ in range(THRESHOLD - 1)]
        say(1, f"  [비밀] s={show(coeffs[0])}, a₁={show(coeffs[1])}, a₂={show(coeffs[2])}"
               f"  → f(x) = s + a₁x + a₂x² (mod q)")
        Y = pow(grp.g, coeffs[0], grp.p)
        say(1, f"  팀 공개키 Y = g^s mod p = {show(Y)}")
        shares = make_shares(coeffs, numbers, grp.q)
        coeffs.clear()
        team = TeamPublic(team_id, key_version, grp, Y,
                          {mid: MemberPublic(mid, numbers[mid], pow(grp.g, s, grp.p)) for mid, s in shares.items()})
        for mid, m in team.members.items():
            say(1, f"    {mid}: x={m.x}  [비밀] s_{mid}=f({m.x})={show(shares[mid])}  y_{mid}=g^s_{mid}={show(m.y)}")
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
        grp = team.grp
        say(1, f"══ 암호화 (작성자 {self.member_id}, 문서 {doc_id} {version}) ══")
        say(1, f"  평문 {len(plaintext)}바이트: {show(plaintext)}")
        k = grp.rand_scalar()
        C1, Z = encapsulate(grp, team.Y, k)
        say(1, f"  [비밀] k={show(k)}")
        say(1, f"  C1 = g^k mod p = {show(C1)}")
        say(1, f"  Z = Y^k mod p = {show(Z)}  (키 재료, 저장하지 않음)")
        del k
        salt = new_salt()
        say(1, f"  salt={show(salt)}")
        round_keys = derive_keys(Z, grp, salt, doc_id, team.key_version, block)
        iv = new_iv(block)
        padded = pad(plaintext, block)
        say(1, f"  IV={show(iv)}, 패딩 후 {show(padded)} ({len(padded) // block.block_bytes}블록,"
               f" {block.bits}비트·{block.rounds}라운드 CBC)")
        ct = cbc_encrypt(padded, iv, round_keys, block)
        rec = DocumentRecord(team_id, doc_id, version, team.key_version, self.member_id, C1, salt, iv,
                             block, ct)
        rec = replace(rec, tag=hmac_tag(mac_key(Z, rec, grp), mac_input(rec)))
        say(1, f"  암호문 {show(ct)}")
        say(1, f"  HMAC 태그 {show(rec.tag)}")
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
        if has_share:
            responses.insert(0, self.respond(server, req))
        say(1, "  부분 복호값 검증")
        chosen = select_partials(team, req, has_share, responses)

        xs = [team.members[p.member_id].x for p in chosen]
        say(1, "  라그랑주 결합 λ_i = Π x_j (x_j − x_i)^{-1} mod q")
        for p, x in zip(chosen, xs):
            lam = lagrange_at_zero(x, xs, grp.q)
            say(1, f"    {p.member_id}: x={x}, d={show(p.d)}, λ={show(lam)}, d^λ mod p={show(pow(p.d, lam, grp.p))}")
        s_star = combine(grp, [(x, p.d) for x, p in zip(xs, chosen)])
        y_t = pow(team.Y, t, grp.p)
        z = unblind(grp, s_star, team.Y, t)
        say(1, f"  S* = Π d^λ mod p = {show(s_star)}  (= B^s)")
        say(1, f"  Y^t = {show(y_t)}, (Y^t)^{{-1}} = {show(pow(y_t, -1, grp.p))}")
        say(1, f"  Z' = S*·(Y^t)^{{-1}} mod p = {show(z)}  (전체 비밀 s는 복원하지 않음)")
        del t
        hmac_verify(mac_key(z, record, grp), mac_input(record), record.tag)
        say(1, "  HMAC 태그 확인 통과 (암호문 변조 없음)")
        round_keys = derive_keys(z, grp, record.salt, record.doc_id, record.key_version, record.block)
        padded = cbc_decrypt(record.ciphertext, record.iv, round_keys, record.block)
        plaintext = unpad(padded, record.block)
        say(1, f"  CBC 복호 {show(padded)} → 패딩 제거 → 평문 {show(plaintext)}")
        return plaintext

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
        d = partial_decrypt(grp, req.b_req, self._share)
        proof = make_proof(grp, req.b_req, self._share, d)
        say(1, f"  {self.member_id}: d_{self.member_id} = B^s_{self.member_id} mod p = {show(d)}, "
               f"증명 (c={show(proof[0])}, z={show(proof[1])})")
        return PartialDecryption(self.member_id, d, proof)


# ──────────────────────────────────────────────────────────────────────────────
# 11) 실행 예
# ──────────────────────────────────────────────────────────────────────────────
def run_flow(grp: Group, block: BlockSpec, numbers: dict[str, int], plaintext: bytes) -> bytes:
    """키 준비 → 조각 전달 → A가 문서 작성 → A·B·D 공동 복호"""
    server = Server()
    members = {mid: Member(mid) for mid in numbers}
    keys = {mid: rsa_keypair() for mid in numbers if mid != "A"}
    team, sealed = members["A"].deal("polygon", "k1", numbers,
                                     {mid: k.public_key() for mid, k in keys.items()}, grp)
    server.register_team(team)
    for mid, blob in sealed.items():
        members[mid].receive_share(server, "polygon", keys[mid], blob)
    members["A"].write_document(server, "polygon", "doc-1", "v1", plaintext, block)
    return members["A"].open_document(server, "polygon", "doc-1", [members["B"], members["D"]])


def demo() -> None:
    previous = TRACE_LEVEL
    set_trace(2)
    print("■ 전체 흐름: [미정] 3072비트 군 · 128비트·12라운드 블록 (s·k·t는 매번 난수, 큰 수는 앞뒤만 표시)")
    out = run_flow(group(), REAL_BLOCK, assign_numbers(list("ABCDE"), group()), "StarPath 기밀 문서".encode())
    print(f"  ▶ 복원 결과 {out.decode()}\n")
    set_trace(previous)

    print("[미정] 보고서에 정의되지 않아 임시값으로 동작하는 부분")
    for name, desc in PROVISIONAL.items():
        print(f"  - {name}: {desc}")


if __name__ == "__main__":
    demo()
