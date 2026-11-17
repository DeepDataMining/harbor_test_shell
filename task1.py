#!/usr/bin/env python3
"""Audit the required files and image-lock.json of one CVE submission.

Usage: python3 audit_submission.py /path/to/CVE-YYYY-NNNN
"""

import argparse
import json
import re
import sys
from pathlib import Path


REQUIRED_FILES = (
    "image-lock.json",
    "harbor-runtime-profile/task.toml",
    "harbor-runtime-profile/instruction.md",
    "harbor-runtime-profile/environment/docker-compose.yaml",
    "harbor-runtime-profile/tests/test.sh",
)
REQUIRED_DIRS = (
    "harbor-runtime-profile",
    "harbor-runtime-profile/environment",
    "harbor-runtime-profile/tests",
)
TIMEOUT_KEY_PATTERN = re.compile(r"^\s*(?:timeout_sec|\"timeout_sec\"|'timeout_sec')\s*=", re.MULTILINE)


def report(ok: bool, label: str, detail: str = "") -> bool:
    print(f"{'✓' if ok else '✗'} {label}{': ' + detail if detail else ''}")
    return ok


def nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def audit(root: Path) -> bool:
    if not root.is_dir():
        report(False, str(root), "输入路径不是文件夹")
        return False

    print(f"审计目录：{root}")
    results = []
    for relative in REQUIRED_DIRS:
        exists = (root / relative).is_dir()
        results.append(report(exists, relative + "/", "存在" if exists else "缺少目录"))
    for relative in REQUIRED_FILES:
        exists = (root / relative).is_file()
        results.append(report(exists, relative, "存在" if exists else "缺少文件"))

    task_config = root / "harbor-runtime-profile/task.toml"
    if task_config.is_file():
        try:
            config_text = task_config.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            results.append(report(False, "task.toml timeout_sec", f"读取失败：{exc}"))
        else:
            has_timeout = bool(TIMEOUT_KEY_PATTERN.search(config_text))
            results.append(report(not has_timeout, "task.toml timeout_sec", "发现配置项" if has_timeout else "未发现配置项"))

    lock_path = root / "image-lock.json"
    if not lock_path.is_file():
        return False
    try:
        with lock_path.open(encoding="utf-8") as file:
            lock = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        report(False, "image-lock.json 格式", str(exc))
        return False

    if not isinstance(lock, dict):
        report(False, "image-lock.json 格式", "顶层必须是 JSON 对象")
        return False
    results.append(report(True, "image-lock.json 格式", "有效 JSON 对象"))

    task = lock.get("task")
    results.append(report(nonempty_string(task) and task.casefold() == root.name.casefold(), "task", f"应为 {root.name}（忽略大小写），实际为 {task!r}"))

    images = lock.get("images")
    valid_images = isinstance(images, list) and bool(images)
    results.append(report(valid_images, "images", "非空数组" if valid_images else "必须是非空数组"))
    if not valid_images:
        return all(results)

    roles = set()
    for index, entry in enumerate(images):
        prefix = f"images[{index}]"
        if not isinstance(entry, dict):
            results.append(report(False, prefix, "必须是对象"))
            continue
        for key in ("role", "ref", "archive"):
            value = entry.get(key)
            results.append(report(nonempty_string(value), f"{prefix}.{key}", "有效" if nonempty_string(value) else "缺少或不是非空字符串"))
        if nonempty_string(entry.get("role")):
            roles.add(entry["role"])

    for role in ("agent", "target"):
        results.append(report(role in roles, f"images role={role}", "存在" if role in roles else "缺少"))

    return all(results)


def main() -> int:
    parser = argparse.ArgumentParser(description="审计单个 CVE 提交目录的必需文件和 image-lock.json")
    parser.add_argument("folder", type=Path, help="CVE-ID 文件夹路径")
    args = parser.parse_args()
    passed = audit(args.folder)
    print("审计结果：" + ("通过" if passed else "未通过"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
