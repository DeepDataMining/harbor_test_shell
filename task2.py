#!/usr/bin/env python3
"""Audit image archives declared by image-lock.json and Docker Compose.

Usage: python3 task2.py /path/to/CVE-ID
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def report(ok: bool, label: str, detail: str = "") -> bool:
    print(f"{'✓' if ok else '✗'} {label}{': ' + detail if detail else ''}")
    return ok


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError("顶层必须是 JSON 对象")
    return data


def load_compose(path: Path) -> dict:
    with path.open(encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict):
        raise ValueError("顶层必须是 YAML 映射")
    return data


def audit(root: Path) -> bool:
    root = root.resolve()
    if not root.is_dir():
        return report(False, str(root), "输入路径不是文件夹")
    if yaml is None:
        return report(False, "PyYAML", "缺少依赖，请安装 python3-yaml 或 PyYAML")

    lock_path = root / "image-lock.json"
    compose_path = root / "harbor-runtime-profile/environment/docker-compose.yaml"
    results = []
    for path in (lock_path, compose_path):
        exists = path.is_file()
        results.append(report(exists, str(path.relative_to(root)), "存在" if exists else "缺少文件"))
    if not all(results):
        return False

    try:
        lock = load_json(lock_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return report(False, "image-lock.json 格式", str(exc))
    try:
        compose = load_compose(compose_path)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        return report(False, "docker-compose.yaml 格式", str(exc))

    images = lock.get("images")
    if not isinstance(images, list) or not images:
        return report(False, "image-lock.json images", "必须是非空数组")
    services = compose.get("services")
    if not isinstance(services, dict) or not services:
        return report(False, "docker-compose.yaml services", "必须是非空映射")

    refs = set()
    allowed_dirs = {root / "images", root.parent / "shared-images"}
    for index, entry in enumerate(images):
        label = f"image-lock.json images[{index}]"
        if not isinstance(entry, dict):
            results.append(report(False, label, "必须是对象"))
            continue
        ref = entry.get("ref")
        archive = entry.get("archive")
        if not isinstance(ref, str) or not ref.strip():
            results.append(report(False, label + ".ref", "缺少镜像名称"))
        else:
            refs.add(ref)
        if not isinstance(archive, str) or not archive.strip():
            results.append(report(False, label + ".archive", "缺少镜像包路径"))
            continue

        # Preserve the submitted symlink's location; resolve() would move it to
        # its source tree and incorrectly reject valid linked archives.
        archive_path = Path(os.path.normpath(root / archive))
        if archive_path.parent not in allowed_dirs:
            results.append(report(False, label + ".archive", "必须位于 images/ 或同级 shared-images/ 目录"))
            continue
        if archive_path.is_symlink() and not archive_path.exists():
            reason = "符号链接目标不存在"
        elif not archive_path.is_file():
            reason = "文件不存在"
        elif archive_path.stat().st_size == 0:
            reason = "文件为空"
        else:
            reason = ""
        results.append(report(not reason, label + ".archive", f"{ref}: {archive_path}" + (f"（{reason}）" if reason else "")))

    for service_name, service in services.items():
        label = f"docker-compose.yaml services.{service_name}.image"
        if not isinstance(service, dict):
            results.append(report(False, str(service_name), "服务配置必须是映射"))
            continue
        image = service.get("image")
        if image is None:
            continue  # 仅使用 build 的服务没有待核对的镜像名称
        if not isinstance(image, str) or not image.strip():
            results.append(report(False, label, "必须是非空镜像名称"))
            continue
        results.append(report(image in refs, label, f"{image}" + (" 已在 image-lock.json 声明" if image in refs else " 未在 image-lock.json 声明")))

    return all(results)


def main() -> int:
    parser = argparse.ArgumentParser(description="检查 image-lock.json 与 Docker Compose 引用的镜像包是否齐全")
    parser.add_argument("folder", type=Path, help="单个 CVE-ID 任务目录")
    args = parser.parse_args()
    passed = audit(args.folder)
    print("审计结果：" + ("通过" if passed else "未通过"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
