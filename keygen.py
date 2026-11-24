"""StarPath 키 생성: 팀 비밀 s, Shamir 조각, 팀 공개키 Y, 검증 공개키 y_i, RSA-OAEP 조각 전달

  generate_team_key() : f(x) = s + a₁x + a₂x² (mod q) → s_i = f(x_i), Y = g^s, y_i = g^{s_i}
  seal_share()        : RSA-OAEP(PK_수신자, (x_i, s_i))
  open_share()        : 봉인 열기
"""

from __future__ import annotations

import secrets
from typing import Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from shared import N_MEMBERS, THRESHOLD, Group, VerificationError, say, show

RSA_KEY_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537
OAEP_HASH: hashes.HashAlgorithm = hashes.SHA256()
MGF1_HASH: hashes.HashAlgorithm = hashes.SHA256()


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


def poly_eval(coeffs: Sequence[int], x: int, q: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % q
    return acc


def make_shares(coeffs: Sequence[int], numbers: dict[str, int], q: int) -> dict[str, int]:
    return {mid: poly_eval(coeffs, x, q) for mid, x in numbers.items()}


def generate_team_key(grp: Group, numbers: dict[str, int]) -> tuple[int, dict[str, int], dict[str, int]]:
    """팀 비밀 s와 계수를 뽑아 조각을 만들고 s·계수는 버림

    반환: (팀 공개키 Y, 참여자별 조각 s_i, 참여자별 검증 공개키 y_i)
    """
    check_numbers(numbers, grp)
    say(1, f"  공개 파라미터 p={show(grp.p)}, q={show(grp.q)}, g={grp.g}, 임계값 {THRESHOLD}-of-{N_MEMBERS}")
    say(1, "  참여자 번호 " + ", ".join(f"{mid}={x}" for mid, x in numbers.items()))
    coeffs = [grp.rand_scalar()] + [secrets.randbelow(grp.q) for _ in range(THRESHOLD - 1)]
    say(1, f"  [비밀] s={show(coeffs[0])}, a₁={show(coeffs[1])}, a₂={show(coeffs[2])}"
           f"  → f(x) = s + a₁x + a₂x² (mod q)")
    Y = pow(grp.g, coeffs[0], grp.p)
    say(1, f"  팀 공개키 Y = g^s mod p = {show(Y)}")
    shares = make_shares(coeffs, numbers, grp.q)
    # [직접 설계] 조각을 만든 뒤 s·계수 폐기
    coeffs.clear()
    ys = {mid: pow(grp.g, s, grp.p) for mid, s in shares.items()}
    for mid, s in shares.items():
        x = numbers[mid]
        say(1, f"    {mid}: x={x}  [비밀] s_{mid}=f({x})={show(s)}  y_{mid}=g^s_{mid}={show(ys[mid])}")
    return Y, shares, ys


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


def encode_share(x: int, share: int) -> bytes:
    out = bytearray()
    for v in (x, share):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        out += len(b).to_bytes(2, "big") + b
    return bytes(out)


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
