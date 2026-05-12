#!/usr/bin/env python3
"""
Extract SAM_SELF_UPDATE script content from app/ssh.py for integration tests.
Uses AST parsing to avoid importing the module (which would require dependencies).
"""
import ast
import sys
from pathlib import Path


def extract_sam_self_update(ssh_py_path: str) -> bytes:
    """Parse ssh.py AST and extract the SAM_SELF_UPDATE constant."""
    with open(ssh_py_path, "r") as f:
        tree = ast.parse(f.read(), filename=ssh_py_path)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SAM_SELF_UPDATE":
                    # Python 3.8+: ast.Constant
                    if hasattr(ast, 'Constant') and isinstance(node.value, ast.Constant):
                        return node.value.value
                    # Python 3.6-3.7: ast.Bytes
                    if isinstance(node.value, ast.Bytes):
                        return node.value.s

    raise ValueError("SAM_SELF_UPDATE constant not found in ssh.py")


if __name__ == "__main__":
    repo_root = Path(__file__).parent.parent.parent
    ssh_py = repo_root / "app" / "ssh.py"

    if not ssh_py.exists():
        print(f"ERROR: {ssh_py} not found", file=sys.stderr)
        sys.exit(1)

    try:
        content = extract_sam_self_update(str(ssh_py))
        sys.stdout.buffer.write(content)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
