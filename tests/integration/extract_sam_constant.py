#!/usr/bin/env python3
"""Extract a top-level bytes constant from app/ssh.py for integration tests.

Uses ast.parse so we never import app/ssh.py (and never pull in paramiko,
psycopg2, the database connection module, …) inside the integration
container.

Usage:  extract_sam_constant.py SAM_COLLECT
"""
import ast
import sys
from pathlib import Path


def extract(ssh_py_path: str, name: str) -> bytes:
    tree = ast.parse(Path(ssh_py_path).read_text(), filename=ssh_py_path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    val = node.value
                    # Python 3.8+: ast.Constant covers bytes literals.
                    if isinstance(val, ast.Constant) and isinstance(
                        val.value, (bytes, bytearray)
                    ):
                        return bytes(val.value)
                    # Python 3.6/3.7 (openSUSE Leap 15 still ships these):
                    # bytes literals parse to ast.Bytes.
                    if hasattr(ast, "Bytes") and isinstance(val, ast.Bytes):
                        return bytes(val.s)
    raise ValueError(f"{name} not found as a bytes constant in {ssh_py_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <CONSTANT_NAME>", file=sys.stderr)
        sys.exit(2)
    repo_root = Path(__file__).parent.parent.parent
    ssh_py = repo_root / "app" / "ssh.py"
    if not ssh_py.is_file():
        print(f"ERROR: {ssh_py} not found", file=sys.stderr)
        sys.exit(1)
    try:
        sys.stdout.buffer.write(extract(str(ssh_py), sys.argv[1]))
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
