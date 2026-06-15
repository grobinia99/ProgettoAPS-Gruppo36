import secrets
from typing import List, Tuple

from config import SHAMIR_FIELD


def _poly_eval(coefficients: List[int], x: int) -> int:
    total = 0
    power = 1
    for coefficient in coefficients:
        total = (total + coefficient * power) % SHAMIR_FIELD
        power = (power * x) % SHAMIR_FIELD
    return total


def shamir_split(secret: bytes, n: int, threshold: int) -> List[Tuple[int, List[int]]]:
    if not 2 <= threshold <= n < SHAMIR_FIELD:
        raise ValueError("Parametri Shamir non validi")
    shares = [(x, []) for x in range(1, n + 1)]
    for byte in secret:
        coefficients = [byte] + [
            secrets.randbelow(SHAMIR_FIELD)
            for _ in range(threshold - 1)
        ]
        for x, values in shares:
            values.append(_poly_eval(coefficients, x))
    return shares


def shamir_reconstruct(
    shares: List[Tuple[int, List[int]]],
    secret_length: int,
) -> bytes:
    if len(shares) < 2:
        raise ValueError("Quote insufficienti")
    if len({x for x, _ in shares}) != len(shares):
        raise ValueError("Quote duplicate")

    output: List[int] = []
    for byte_index in range(secret_length):
        value = 0
        for i, (xi, yi_values) in enumerate(shares):
            if len(yi_values) != secret_length:
                raise ValueError("Lunghezza quota non valida")
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator = (numerator * (-xj)) % SHAMIR_FIELD
                    denominator = (denominator * (xi - xj)) % SHAMIR_FIELD
            lagrange = (
                numerator
                * pow(denominator % SHAMIR_FIELD, -1, SHAMIR_FIELD)
            )
            value = (value + yi_values[byte_index] * lagrange) % SHAMIR_FIELD

        if value > 255:
            raise ValueError("Ricostruzione Shamir non valida")
        output.append(value)
    return bytes(output)
