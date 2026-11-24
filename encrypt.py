"""StarPath 암호화: ElGamal 캡슐화 → HKDF 키 유도 → SPN 블록 암호(CBC) → HMAC 태그

  encapsulate()      : C1 = g^k, Z = Y^k
  spn_encrypt()      : ⊕RK → AES S-Box(바이트) → 재배열(m=3/5) → 행 XOR 확산 (마지막 라운드 확산 생략) → ⊕RK_f
  cbc_encrypt()      : CBC 모드
  encrypt_document() : 위 과정을 묶어 문서 레코드 생성 (k·Z는 함수 밖으로 나가지 않음)
"""

from __future__ import annotations

import secrets
from dataclasses import replace
from typing import Sequence

from shared import (REAL_BLOCK, SALT_BYTES, BlockSpec, DocumentRecord, Group, check_block,
                    derive_keys, from_nibbles, hexw, hmac_tag, mac_input, mac_key, perm_multiplier,
                    say, show, sub_bytes, to_nibbles)


def encapsulate(grp: Group, Y: int, k: int) -> tuple[int, int]:
    """C1 = g^k, Z = Y^k"""
    return pow(grp.g, k, grp.p), pow(Y, k, grp.p)


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def permute(ns: list[int], m: int) -> list[int]:
    n = len(ns)
    # [직접 설계] 위치 재배열 S'[j] = S[(m·j) mod n]
    return [ns[(m * j) % n] for j in range(n)]


def diffuse(ns: list[int]) -> list[int]:
    out = []
    for i in range(0, len(ns), 4):
        a, b, c, d = ns[i:i + 4]
        # [직접 설계] 행 단위 XOR 확산 (a, b, c, d) → (a⊕b, b⊕c, c⊕d, d⊕a⊕b)
        out += [a ^ b, b ^ c, c ^ d, d ^ a ^ b]
    return out


def spn_encrypt(block: int, round_keys: Sequence[int], spec: BlockSpec = REAL_BLOCK) -> int:
    """round_keys = [RK_1 … RK_R, RK_final]. 마지막 라운드는 확산 생략 후 최종 키 XOR"""
    check_block(block, round_keys, spec)
    n, state = spec.nibbles, block
    for r in range(spec.rounds):
        rk = round_keys[r]
        # [직접 설계] 라운드 = 키 XOR → AES S-Box(1바이트씩) → 재배열 → 확산, 마지막 라운드는 확산 생략 후 최종 키 XOR
        x = state ^ rk
        sb = sub_bytes(x, spec.block_bytes)
        ns = to_nibbles(sb, n)
        m = perm_multiplier(rk, n)
        ns = permute(ns, m)
        pm = from_nibbles(ns)
        if r < spec.rounds - 1:
            ns = diffuse(ns)
        state = from_nibbles(ns)
        say(2, f"        R{r + 1}: ⊕RK {hexw(x, n)} → AES S-Box {hexw(sb, n)} → 재배열(m={m}) {hexw(pm, n)}"
               + (f" → 확산 {hexw(state, n)}" if r < spec.rounds - 1 else " (확산 생략)"))
    out = state ^ round_keys[-1]
    say(2, f"        ⊕RK_f → {hexw(out, n)}")
    return out


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


def pad(data: bytes, spec: BlockSpec = REAL_BLOCK) -> bytes:
    n = spec.block_bytes - len(data) % spec.block_bytes
    return data + bytes([n]) * n


def new_iv(spec: BlockSpec = REAL_BLOCK) -> bytes:
    return secrets.token_bytes(spec.block_bytes)


def encrypt_document(grp: Group, Y: int, team_id: str, doc_id: str, version: str, key_version: str,
                     author_id: str, plaintext: bytes, block: BlockSpec = REAL_BLOCK) -> DocumentRecord:
    """k 생성 → C1·Z → salt → 라운드 키 → IV·패딩 → CBC → HMAC 태그"""
    say(1, f"  평문 {len(plaintext)}바이트: {show(plaintext)}")
    k = grp.rand_scalar()
    C1, Z = encapsulate(grp, Y, k)
    say(1, f"  [비밀] k={show(k)}")
    say(1, f"  C1 = g^k mod p = {show(C1)}")
    say(1, f"  Z = Y^k mod p = {show(Z)}  (키 재료, 저장하지 않음)")
    del k
    salt = new_salt()
    say(1, f"  salt={show(salt)}")
    round_keys = derive_keys(Z, grp, salt, doc_id, key_version, block)
    iv = new_iv(block)
    padded = pad(plaintext, block)
    say(1, f"  IV={show(iv)}, 패딩 후 {show(padded)} ({len(padded) // block.block_bytes}블록,"
           f" {block.bits}비트·{block.rounds}라운드 CBC)")
    ct = cbc_encrypt(padded, iv, round_keys, block)
    rec = DocumentRecord(team_id, doc_id, version, key_version, author_id, C1, salt, iv, block, ct)
    rec = replace(rec, tag=hmac_tag(mac_key(Z, rec, grp), mac_input(rec)))
    say(1, f"  암호문 {show(ct)}")
    say(1, f"  HMAC 태그 {show(rec.tag)}")
    return rec
