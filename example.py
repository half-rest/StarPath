"""StarPath 실행 예: 키 준비 → 조각 전달 → 문서 암호화 → 3명 공동 복호

실행: python example.py
"""

import starpath_service as sp


def run_flow(numbers: dict[str, int], plaintext: bytes) -> bytes:
    """A가 배포·작성하고, A·B·D가 공동 복호"""
    grp = sp.group()
    server = sp.Server()
    members = {mid: sp.Member(mid) for mid in numbers}
    keys = {mid: sp.rsa_keypair() for mid in numbers if mid != "A"}

    team, sealed = members["A"].deal("polygon", "k1", numbers,
                                     {mid: k.public_key() for mid, k in keys.items()}, grp)
    server.register_team(team)
    for mid, blob in sealed.items():
        members[mid].receive_share(server, "polygon", keys[mid], blob)

    members["A"].write_document(server, "polygon", "doc-1", "v1", plaintext, sp.REAL_BLOCK)
    return members["A"].open_document(server, "polygon", "doc-1", [members["B"], members["D"]])


def main() -> None:
    sp.set_trace(2)
    print("■ 전체 흐름: [미정] 3072비트 군 · 128비트·12라운드 블록 (s·k·t는 매번 난수, 큰 수는 앞뒤만 표시)")
    numbers = sp.assign_numbers(list("ABCDE"), sp.group())
    out = run_flow(numbers, "StarPath 기밀 문서".encode())
    print(f"  ▶ 복원 결과 {out.decode()}\n")

    print("[미정] 보고서에 정의되지 않아 임시값으로 동작하는 부분")
    for name, desc in sp.PROVISIONAL.items():
        print(f"  - {name}: {desc}")


if __name__ == "__main__":
    main()
