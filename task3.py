#!/usr/bin/env python3
"""Start one local Harbor task environment and save the startup log.

Example:
    python3 task3.py --bundle /path/to/bundle --task-id CVE-YYYY-NNNN \
        --work /tmp/harbor-startup --load-images
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def run_logged(command: list[str], log_path: Path) -> int:
    with log_path.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
        log.write(f"退出码：{result.returncode}\n")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="单次检查本地 Harbor 靶场环境能否启动")
    parser.add_argument("--bundle", required=True, type=Path, help="交付 bundle 根目录")
    parser.add_argument("--task-id", required=True, help="任务目录名称")
    parser.add_argument("--work", required=True, type=Path, help="日志工作目录")
    parser.add_argument("--load-images", action="store_true", help="启动前加载本地镜像")
    args = parser.parse_args()

    bundle = args.bundle.resolve()
    if not bundle.is_dir():
        parser.error(f"bundle 目录不存在：{bundle}")
    if not args.task_id or Path(args.task_id).name != args.task_id or args.task_id in (".", ".."):
        parser.error("--task-id 必须是单个任务目录名称")

    runtime = bundle / args.task_id / "harbor-runtime-profile"
    if not runtime.is_dir():
        parser.error(f"Harbor 运行目录不存在：{runtime}")
    if not (runtime / "task.toml").is_file():
        parser.error(f"缺少任务配置：{runtime / 'task.toml'}")

    harbor = shutil.which("harbor")
    if harbor is None:
        parser.error("找不到 harbor 命令，请先安装并加入 PATH")
    loader = bundle / "bin" / "load_image.py"
    if args.load_images and not loader.is_file():
        parser.error(f"镜像加载脚本不存在：{loader}")

    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    log_path = work / "start-env.log"

    if args.load_images:
        print("加载镜像中……", flush=True)
        code = run_logged(
            [sys.executable, str(loader), "--root", str(bundle), "--task", args.task_id],
            log_path,
        )
        if code != 0:
            print(f"✗ 镜像加载失败（退出码 {code}），日志：{log_path}")
            return code

    print("启动本地 Harbor 环境中……", flush=True)
    code = run_logged([harbor, "task", "start-env", "--path", str(runtime), "--non-interactive"], log_path)
    if code == 0:
        print(f"✓ 环境启动成功，日志：{log_path}")
    else:
        print(f"✗ 环境启动失败（退出码 {code}），日志：{log_path}")
    return code


if __name__ == "__main__":
    sys.exit(main())
