# Comic Organizer

这是一个整理漫画压缩包 / 电子书文件的 Python 小项目版本。

## 功能特性

- 支持三种扫描模式：`safe` / `repair` / `full`
- 支持 `dry-run` 预演，避免直接误操作
- 支持正式执行与二次确认
- 支持基于体积 + 快速哈希 + 全量哈希的重复检测
- 支持基于标题归一化的疑似重复检测
- 支持 `.history/` 历史会话记录
- 支持执行回滚
- 支持多种压缩包和电子书格式：`zip`、`rar`、`7z`、`cbz`、`cbr`、`epub`、`pdf`、`mobi`、`azw3`

## 使用方式

### 直接运行

```bash
python3 -m comic_organizer /path/to/source --dry-run
```

### 可选：可编辑安装

```bash
pip install -e .
comic-organizer /path/to/source --dry-run
```

## 常用命令

```bash
python3 -m comic_organizer /path/to/source --dry-run --scan-mode safe
python3 -m comic_organizer /path/to/source --execute --scan-mode repair --yes
python3 -m comic_organizer /path/to/source --list-sessions
python3 -m comic_organizer /path/to/source --rollback latest
```

## 项目结构

```text
.
├── comic_organizer/
│   ├── __init__.py
│   ├── __main__.py
│   └── cli.py
├── pyproject.toml
├── README.md
├── README.zh-CN.md
└── .gitignore
```

## 说明

- 当前版本采用“保守项目化”方案：先把原始脚本安全迁移为包内 `cli.py`
- 这样可以先完成仓库化和命令入口整理，再逐步继续拆分模块
- 后续可继续拆为 `config.py`、`session.py`、`detector.py`、`organizer.py` 等
- 运行产生的 `.history/` 和 `整理日志.txt` 已加入 Git 忽略
