"""StarPath 복호화: 블라인딩 → 부분 복호·증명 → 라그랑주 결합 → 블라인딩 제거 → MAC 확인 → SPN 역연산(CBC)

  blind()            : B = C1 · g^t                          (요청자)
  partial_decrypt()  : d_i = B^{s_i}, make_proof()            (협력자)
  verify_partial()   : 증명 확인                               (요청자)
  recover_z()        : S* = Π d_i^{λ_i}, Z' = S* · (Y^t)^{-1}  (요청자)
  decrypt_document() : HMAC 확인 → 키 유도 → CBC 복호 → 패딩 제거
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Sequence

from shared import (MAC_HASH, REAL_BLOCK, SBOX, THRESHOLD, BlockSpec, DocumentRecord, Group,
                    VerificationError, check_block, derive_keys, encode_fields, from_nibbles, hexw,
                    hmac_tag, mac_input, mac_key, perm_multiplier, provisional, say, show, to_nibbles)

INV_SBOX = [SBOX.index(i) for i in range(16)]


def blind(grp: Group, C1: int, t: int) -> int:
    """B = C1 · g^t"""
    return C1 * pow(grp.g, t, grp.p) % grp.p


def partial_decrypt(grp: Group, b: int, share: int) -> int:
    """d_i = B^{s_i}"""
    return pow(b, share, grp.p)


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


def lagrange_at_zero(xi: int, xs: Sequence[int], q: int) -> int:
    """λ_i = Π_{j≠i} x_j (x_j − x_i)^{-1}  (mod q)"""
    num, den = 1, 1
    for xj in xs:
        if xj != xi:
            num = num * xj % q
            den = den * (xj - xi) % q
    return num * pow(den, -1, q) % q


def combine(grp: Group, points: Sequence[tuple[int, int]]) -> int:
    """S* = Π d_i^{λ_i}  (mod p)"""
    xs = [x for x, _ in points]
    # [직접 설계] 정확히 τ명의 서로 다른 값만 결합
    if len(points) != THRESHOLD or len(set(xs)) != THRESHOLD:
        raise PermissionError(f"정확히 {THRESHOLD}명의 서로 다른 값이 필요함")
    s_star = 1
    for x, d in points:
        s_star = s_star * pow(d, lagrange_at_zero(x, xs, grp.q), grp.p) % grp.p
    return s_star


def unblind(grp: Group, s_star: int, Y: int, t: int) -> int:
    """Z' = S* · (Y^t)^{-1}"""
    return s_star * pow(pow(Y, t, grp.p), -1, grp.p) % grp.p


def recover_z(grp: Group, Y: int, t: int, partials: Sequence[tuple[str, int, int]]) -> int:
    """partials = [(참여자 ID, 번호 x_i, d_i)] τ개 → Z'. 전체 비밀 s는 복원하지 않음"""
    xs = [x for _, x, _ in partials]
    say(1, "  라그랑주 결합 λ_i = Π x_j (x_j − x_i)^{-1} mod q")
    for mid, x, d in partials:
        lam = lagrange_at_zero(x, xs, grp.q)
        say(1, f"    {mid}: x={x}, d={show(d)}, λ={show(lam)}, d^λ mod p={show(pow(d, lam, grp.p))}")
    s_star = combine(grp, [(x, d) for _, x, d in partials])
    y_t = pow(Y, t, grp.p)
    # [직접 설계] S* = B^s에서 요청자가 Y^t를 제거해 Z 복원, 전체 비밀 s는 복원하지 않음
    z = unblind(grp, s_star, Y, t)
    say(1, f"  S* = Π d^λ mod p = {show(s_star)}  (= B^s)")
    say(1, f"  Y^t = {show(y_t)}, (Y^t)^{{-1}} = {show(pow(y_t, -1, grp.p))}")
    say(1, f"  Z' = S*·(Y^t)^{{-1}} mod p = {show(z)}  (전체 비밀 s는 복원하지 않음)")
    return z


def inv_permute(ns: list[int], m: int) -> list[int]:
    n = len(ns)
    out = [0] * n
    for j in range(n):
        # [직접 설계] 재배열의 역연산
        out[(m * j) % n] = ns[j]
    return out


def inv_diffuse(ns: list[int]) -> list[int]:
    out = []
    for i in range(0, len(ns), 4):
        p, q, s1, s2 = ns[i:i + 4]
        # [직접 설계] 확산의 역연산 (d, c, b, a 순서로 되풂)
        d = s2 ^ p
        c = s1 ^ d
        b = q ^ c
        a = p ^ b
        out += [a, b, c, d]
    return out


def spn_decrypt(block: int, round_keys: Sequence[int], spec: BlockSpec = REAL_BLOCK) -> int:
    check_block(block, round_keys, spec)
    n, state = spec.nibbles, block ^ round_keys[-1]
    say(2, f"        ⊕RK_f → {hexw(state, n)}")
    for r in range(spec.rounds - 1, -1, -1):
        rk = round_keys[r]
        ns = to_nibbles(state, n)
        # [직접 설계] 암호화 라운드의 역순 (마지막 라운드는 역확산 생략)
        if r < spec.rounds - 1:
            ns = inv_diffuse(ns)
        m = perm_multiplier(rk, n)
        ns = inv_permute(ns, m)
        state = from_nibbles([INV_SBOX[v] for v in ns]) ^ rk
        say(2, f"        R{r + 1} 역: " + ("역확산 → " if r < spec.rounds - 1 else "")
               + f"역재배열(m={m}) → 역 S-Box → ⊕RK = {hexw(state, n)}")
    return state


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


@provisional("CBC 패딩 = PKCS#7 (MAC 확인 뒤에만 호출)")
def unpad(data: bytes, spec: BlockSpec = REAL_BLOCK) -> bytes:
    if not data or len(data) % spec.block_bytes:
        raise VerificationError("패딩 길이가 잘못됨")
    n = data[-1]
    if not 1 <= n <= spec.block_bytes or data[-n:] != bytes([n]) * n:
        raise VerificationError("패딩이 잘못됨")
    return data[:-n]


def hmac_verify(key: bytes, data: bytes, tag: bytes, hash_name: str | None = None) -> None:
    if not hmac.compare_digest(hmac_tag(key, data, hash_name or MAC_HASH), tag):
        raise VerificationError("MAC 불일치: 변조된 암호문")


def decrypt_document(grp: Group, z: int, record: DocumentRecord) -> bytes:
    """Z' → HMAC 확인 → 라운드 키 → CBC 복호 → 패딩 제거"""
    hmac_verify(mac_key(z, record, grp), mac_input(record), record.tag)
    say(1, "  HMAC 태그 확인 통과 (암호문 변조 없음)")
    round_keys = derive_keys(z, grp, record.salt, record.doc_id, record.key_version, record.block)
    padded = cbc_decrypt(record.ciphertext, record.iv, round_keys, record.block)
    plaintext = unpad(padded, record.block)
    say(1, f"  CBC 복호 {show(padded)} → 패딩 제거 → 평문 {show(plaintext)}")
    return plaintext
