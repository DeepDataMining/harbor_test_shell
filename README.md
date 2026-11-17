# Harbor 交付校验

按[交付规范](https://aicarrier.feishu.cn/wiki/ENbHwnS0ciy2CgkojPzc0ZPinkf?from=from_parent_docx)准备任务目录。以下命令在 `Judger/` 目录执行；`<CVE目录>` 可以是相对路径或绝对路径。脚本检查失败时返回非零退出码。

## 1. 文件与配置

```bash
python3 task1.py <CVE目录>
```

检查必需文件和目录、`images/*.tar.gz`，以及 `image-lock.json` 的 `task`、`images`、`role/ref/archive` 字段。若 `task.toml` 中配置了 `timeout_sec`，审计不通过。`environment/assets/` 可选。通过时输出 `审计结果：通过`。

## 2. 镜像包

```bash
python3 task2.py <CVE目录>
```

检查 lock 中的镜像包位于任务 `images/` 或同级 `shared-images/`，文件存在且非空；同时检查 Compose 的 `image` 是否在 lock 中声明。符号链接必须能指向实际文件。需要安装 PyYAML。通过时输出 `审计结果：通过`。

## 3. 本地环境启动

先确认当前环境能运行 `harbor --version`；若提示找不到命令，先激活 Harbor 环境或将其 `bin` 目录加入 `PATH`。

```bash
python3 task3.py --bundle /path/to/bundle --task-id CVE-YYYY-NNNN --work /path/to/work --load-images
```

`--bundle` 指向包含任务目录的父目录，不能指向任务目录本身。`--load-images` 可省略；使用它时 bundle 内需有 `bin/load_image.py`。脚本调用 `harbor task start-env`，结果写入工作目录的 `start-env.log`；成功时输出 `环境启动成功`。此步骤不运行模型，也不验证解题奖励。


## 4. 补充

建议随任务提供 `solution/`，供后续解题验收。后续验收评测还会检查运行轨迹与奖励结果，防止hack现象。
