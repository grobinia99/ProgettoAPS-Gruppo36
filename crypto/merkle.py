import hmac
from typing import List

from crypto.base_utils import sha256_hex


def _leaf_hash(value: str) -> str:
    return sha256_hex(value.encode("utf-8"))


def _node_hash(left: str, right: str) -> str:
    return sha256_hex((left + right).encode("ascii"))


def build_merkle_tree(values: List[str]) -> List[List[str]]:
    if not values:
        return [[sha256_hex(b"")]]
    level = [_leaf_hash(value) for value in values]
    tree = [level]
    while len(level) > 1:
        current = list(level)
        if len(current) % 2:
            current.append(current[-1])
        level = [
            _node_hash(current[i], current[i + 1])
            for i in range(0, len(current), 2)
        ]
        tree.append(level)
    return tree


def merkle_root(values: List[str]) -> str:
    return build_merkle_tree(values)[-1][0]


def merkle_proof(values: List[str], target: str) -> List[dict]:
    if target not in values:
        raise ValueError("Elemento non presente nel Merkle tree")
    index = values.index(target)
    tree = build_merkle_tree(values)
    proof: List[dict] = []
    for level in tree[:-1]:
        current = list(level)
        if len(current) % 2:
            current.append(current[-1])
        sibling_index = index ^ 1
        proof.append({
            "hash": current[sibling_index],
            "position": "right" if index % 2 == 0 else "left",
        })
        index //= 2
    return proof


def verify_merkle_proof(value: str, proof: List[dict], expected_root: str) -> bool:
    current = _leaf_hash(value)
    for item in proof:
        sibling = item.get("hash")
        position = item.get("position")
        if not isinstance(sibling, str) or position not in {"left", "right"}:
            return False
        current = (
            _node_hash(current, sibling)
            if position == "right"
            else _node_hash(sibling, current)
        )
    return hmac.compare_digest(current, expected_root)
