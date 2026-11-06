#!/usr/bin/env python3
"""晚点名自动签到入口：读取本地凭据、调用 signin.py、失败后重试。"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
SIGNIN = ROOT / "signin.py"
LOG_DIR = ROOT / "logs"
FZU_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")

INITIAL_DELAY_SEC = 60
MAX_DELAY_SEC = 300
STOP_HOUR, STOP_MINUTE = 23, 59

PERMANENT_FAIL_MARKERS = (
    "账号密码错误",
    "SSO 登录失败",
    "密码不能为空",
    "需要短信两步验证",
    "两步验证",
    "短信验证码不能为空",
    "验证码校验失败",
)

ALREADY_DONE_MARKERS = (
    "请勿重复打卡",
    "[成功] 签到完成",
    "[跳过] 今日已签到",
    "[跳过] 今日无需签到",
)


def now_fzu() -> datetime:
    return datetime.now(FZU_TZ)


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise FileNotFoundError(f"找不到凭据文件: {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def deadline_for(start: datetime) -> datetime:
    stop = start.replace(hour=STOP_HOUR, minute=STOP_MINUTE, second=0, microsecond=0)
    if start >= stop:
        return start + timedelta(hours=2)
    return stop


def is_permanent_failure(text: str) -> bool:
    return any(marker in text for marker in PERMANENT_FAIL_MARKERS)


def append_log(log_path: Path, text: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")


def run_once(env: dict[str, str], extra_args: list[str], log_path: Path) -> tuple[int, str]:
    child_env = os.environ.copy()
    child_env.update(env)
    child_env.setdefault("PYTHONIOENCODING", "utf-8")
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.run(
        [sys.executable, str(SIGNIN), *extra_args],
        cwd=str(ROOT),
        env=child_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    append_log(log_path, output.rstrip() + "\n")
    return proc.returncode, output


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    start = now_fzu()
    log_path = LOG_DIR / f"signin-{start.strftime('%Y-%m-%d')}.log"
    deadline = deadline_for(start)

    file_env = load_env(ENV_FILE)
    username = file_env.get("FZU_USERNAME", "").strip()
    password = file_env.get("FZU_PASSWORD", "").strip()
    if not username or not password:
        msg = "[错误] .env 中缺少 FZU_USERNAME 或 FZU_PASSWORD"
        print(msg)
        append_log(log_path, f"\n===== {start.isoformat()} =====\n{msg}\n")
        return 1

    env = {
        "FZU_USERNAME": username,
        "FZU_PASSWORD": password,
    }
    extra_args: list[str] = []
    if file_env.get("FZU_LON", "").strip():
        extra_args.extend(["--lon", file_env["FZU_LON"].strip()])
    if file_env.get("FZU_LAT", "").strip():
        extra_args.extend(["--lat", file_env["FZU_LAT"].strip()])
    if file_env.get("FZU_ADDRESS", "").strip():
        extra_args.extend(["--address", file_env["FZU_ADDRESS"].strip()])

    delay = INITIAL_DELAY_SEC
    attempt = 0
    append_log(
        log_path,
        f"\n===== {start.isoformat()} 开始自动签到 "
        f"(截止 {deadline.strftime('%H:%M')}) =====\n",
    )

    while True:
        attempt += 1
        stamp = now_fzu().strftime("%H:%M:%S")
        header = f"[自动签到] {stamp} 第 {attempt} 次尝试"
        print(header)
        append_log(log_path, header + "\n")

        code, output = run_once(env, extra_args, log_path)
        print(output.rstrip())

        if code == 0 or any(marker in output for marker in ALREADY_DONE_MARKERS):
            print("[自动签到] 完成")
            append_log(log_path, "[自动签到] 完成\n")
            return 0

        if is_permanent_failure(output):
            print("[自动签到] 遇到不可自动恢复的错误，停止重试")
            append_log(log_path, "[自动签到] 遇到不可自动恢复的错误，停止重试\n")
            return 1

        remaining = (deadline - now_fzu()).total_seconds()
        if remaining <= 0:
            print("[自动签到] 已到截止时间，今晚不再重试")
            append_log(log_path, "[自动签到] 已到截止时间，今晚不再重试\n")
            return 1

        sleep_for = min(delay, max(1, int(remaining)))
        print(f"[自动签到] 失败，{sleep_for} 秒后重试")
        append_log(log_path, f"[自动签到] 失败，{sleep_for} 秒后重试\n")
        time.sleep(sleep_for)
        delay = min(int(delay * 1.5), MAX_DELAY_SEC)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
