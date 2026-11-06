#!/usr/bin/env python3
"""福大晚点名签到助手：窗口配置 + 计划任务 + 失败重试到 23:59。"""

from __future__ import annotations

import argparse
import base64
import ctypes
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from contextlib import redirect_stderr, redirect_stdout
from ctypes import POINTER, Structure, byref, c_char, create_string_buffer, windll
from ctypes.wintypes import DWORD
from datetime import datetime, timedelta, timezone
from pathlib import Path

import signin

APP_NAME = "福大晚点名签到"
APP_VERSION = "1.1.0"
TASK_NAME = "福大晚点名签到"
OLD_TASK_NAMES = ("福大晚点名签到", "FZU晚点名签到")
FZU_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")
INITIAL_DELAY_SEC = 60
MAX_DELAY_SEC = 300
DONE_POLL_SEC = 5
# 计划任务 WakeToRun 可能提前一两分钟叫醒，短于此时长就等到点再签。
EARLY_START_GRACE_SEC = 180
STOP_HOUR, STOP_MINUTE = 23, 59

QISHAN_PRESET = {
    "lon": 119.188916,
    "lat": 26.058772,
    "address": "旗山校区 学府北路10-165号",
}

PERMANENT_FAIL_MARKERS = (
    "账号密码错误",
    "SSO 登录失败",
    "密码不能为空",
    "需要短信两步验证",
    "短信验证码不能为空",
    "验证码校验失败",
)
ALREADY_DONE_MARKERS = (
    "请勿重复打卡",
    "[成功] 签到完成",
    "[跳过] 今日已签到",
    "[跳过] 今日无需签到",
)


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def data_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    path = Path(base) / "FZUAttn"
    path.mkdir(parents=True, exist_ok=True)
    return path


CONFIG_PATH = data_dir() / "config.json"
LOG_DIR = data_dir() / "logs"


class DATA_BLOB(Structure):
    _fields_ = [("cbData", DWORD), ("pbData", POINTER(c_char))]


def dpapi_encrypt(text: str) -> str:
    raw = text.encode("utf-8")
    buf = create_string_buffer(raw, len(raw))
    blob_in = DATA_BLOB(len(raw), buf)
    blob_out = DATA_BLOB()
    if not windll.crypt32.CryptProtectData(
        byref(blob_in), None, None, None, None, 0, byref(blob_out)
    ):
        raise OSError("无法加密保存密码")
    try:
        protected = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        windll.kernel32.LocalFree(blob_out.pbData)
    return base64.b64encode(protected).decode("ascii")


def dpapi_decrypt(payload: str) -> str:
    raw = base64.b64decode(payload)
    buf = create_string_buffer(raw, len(raw))
    blob_in = DATA_BLOB(len(raw), buf)
    blob_out = DATA_BLOB()
    if not windll.crypt32.CryptUnprotectData(
        byref(blob_in), None, None, None, None, 0, byref(blob_out)
    ):
        raise OSError("无法读取已保存的密码，请重新输入")
    try:
        plain = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        windll.kernel32.LocalFree(blob_out.pbData)
    return plain.decode("utf-8")


def default_config() -> dict:
    return {
        "username": "",
        "password": "",
        "hour": 21,
        "minute": 30,
        "lon": QISHAN_PRESET["lon"],
        "lat": QISHAN_PRESET["lat"],
        "address": QISHAN_PRESET["address"],
        "sendkey": "",
    }


def load_config() -> dict:
    cfg = default_config()
    if not CONFIG_PATH.is_file():
        return cfg
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return cfg
    if not isinstance(data, dict):
        return cfg
    cfg["username"] = str(data.get("username") or "")
    cfg["hour"] = int(data.get("hour") if data.get("hour") is not None else 21)
    cfg["minute"] = int(data.get("minute") if data.get("minute") is not None else 30)
    cfg["lon"] = float(data.get("lon") if data.get("lon") is not None else QISHAN_PRESET["lon"])
    cfg["lat"] = float(data.get("lat") if data.get("lat") is not None else QISHAN_PRESET["lat"])
    cfg["address"] = str(data.get("address") or QISHAN_PRESET["address"])
    cfg["sendkey"] = ""
    secret = data.get("password_dpapi") or ""
    if secret:
        try:
            cfg["password"] = dpapi_decrypt(str(secret))
        except Exception:
            cfg["password"] = ""
    sendkey = data.get("sendkey_dpapi") or ""
    if sendkey:
        try:
            cfg["sendkey"] = dpapi_decrypt(str(sendkey))
        except Exception:
            cfg["sendkey"] = ""
    return cfg


def save_config(cfg: dict) -> None:
    payload = {
        "username": cfg["username"],
        "password_dpapi": dpapi_encrypt(cfg["password"]),
        "hour": int(cfg["hour"]),
        "minute": int(cfg["minute"]),
        "lon": float(cfg["lon"]),
        "lat": float(cfg["lat"]),
        "address": cfg["address"],
        "sendkey_dpapi": dpapi_encrypt(cfg.get("sendkey") or "") if cfg.get("sendkey") else "",
    }
    CONFIG_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def now_fzu() -> datetime:
    return datetime.now(FZU_TZ)


def log_path_for(dt: datetime | None = None) -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    day = (dt or now_fzu()).strftime("%Y-%m-%d")
    return LOG_DIR / f"signin-{day}.log"


def append_log(text: str) -> None:
    path = log_path_for()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")


def deadline_for(start: datetime) -> datetime:
    stop = start.replace(hour=STOP_HOUR, minute=STOP_MINUTE, second=0, microsecond=0)
    if start >= stop:
        return start + timedelta(minutes=5)
    return stop


def signin_window(now: datetime, hour: int, minute: int) -> tuple[datetime, datetime]:
    begin = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
    end = now.replace(hour=STOP_HOUR, minute=STOP_MINUTE, second=59, microsecond=0)
    return begin, end


def is_success_text(text: str) -> bool:
    return any(marker in text for marker in ALREADY_DONE_MARKERS)


def is_permanent_failure(text: str) -> bool:
    return any(marker in text for marker in PERMANENT_FAIL_MARKERS)


def done_flag_path(dt: datetime | None = None) -> Path:
    day = (dt or now_fzu()).strftime("%Y-%m-%d")
    return data_dir() / f"done-{day}.flag"


def mark_today_done(source: str) -> None:
    done_flag_path().write_text(f"{now_fzu().isoformat()} {source}\n", encoding="utf-8")


def today_is_done() -> bool:
    if done_flag_path().is_file():
        return True
    log = log_path_for()
    if not log.is_file():
        return False
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(marker in text for marker in ALREADY_DONE_MARKERS)


def wait_or_done(seconds: int) -> bool:
    """休眠等待重试；若今日已由其他方式签到则立即返回 True。"""
    deadline = time.monotonic() + max(0, int(seconds))
    while True:
        if today_is_done():
            return True
        left = deadline - time.monotonic()
        if left <= 0:
            return today_is_done()
        time.sleep(min(DONE_POLL_SEC, left))


def run_signin_once(cfg: dict, ask_sms=None) -> tuple[bool, str]:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            signin.reset_session()
            cookie = signin.sso_login(cfg["username"], cfg["password"], ask_sms=ask_sms)
            token = signin.get_attn_token(cookie)
            print(f"[换token] 成功: {token[:12]}...{token[-6:]}")
            signin.do_signin(token, float(cfg["lon"]), float(cfg["lat"]), str(cfg["address"]))
        output = buf.getvalue()
        return True, output
    except Exception as exc:
        output = buf.getvalue() + f"\n[错误] {exc}"
        return False, output.strip() + "\n"


def run_signin_with_retry(cfg: dict | None = None, ask_sms=None, on_status=None) -> int:
    start = now_fzu()
    saved = load_config()
    begin, end = signin_window(
        start, int(saved.get("hour") or 21), int(saved.get("minute") or 30)
    )
    if start > end:
        msg = (
            f"[自动签到] 已过今日截止 {end.strftime('%H:%M')}，"
            f"当前 {start.strftime('%H:%M')}，跳过。"
        )
        append_log(f"\n===== {start.isoformat()} =====\n{msg}\n")
        if on_status:
            on_status(msg)
        return 0
    if start < begin:
        wait_sec = (begin - start).total_seconds()
        if wait_sec > EARLY_START_GRACE_SEC:
            msg = (
                f"[自动签到] 未到今日签到时段 {begin.strftime('%H:%M')}-"
                f"{end.strftime('%H:%M')}，当前 {start.strftime('%H:%M')}。"
                "这是关机后开机补跑的任务，已跳过；今晚到点会再自动签到。"
            )
            append_log(f"\n===== {start.isoformat()} =====\n{msg}\n")
            if on_status:
                on_status(msg)
            return 0
        append_log(
            f"\n===== {start.isoformat()} =====\n"
            f"[自动签到] 距 {begin.strftime('%H:%M')} 还差 {int(wait_sec)} 秒，等到点再签\n"
        )
        time.sleep(wait_sec)
        start = now_fzu()

    deadline = deadline_for(start)
    delay = INITIAL_DELAY_SEC
    attempt = 0
    append_log(
        f"\n===== {start.isoformat()} 开始自动签到 "
        f"(截止 {deadline.strftime('%H:%M')}) =====\n"
    )
    if today_is_done():
        append_log("[自动签到] 今日已签到，跳过\n")
        if on_status:
            on_status("今日已签到，跳过")
        return 0

    while True:
        if today_is_done():
            append_log("[自动签到] 今日已由其他方式完成，停止重试\n")
            if on_status:
                on_status("今日已签到，停止重试")
            return 0

        # 每次重试都重新读配置，避免窗口里改过密码后自动任务仍用启动时的旧密码。
        cfg = load_config()
        if not cfg.get("username") or not cfg.get("password"):
            output = (
                "[错误] 尚未保存学号或密码。"
                "请在窗口点「保存并创建计划任务」，或先「立即试签一次」（试签会自动保存）。"
            )
            append_log(output + "\n")
            ok = False
        else:
            attempt += 1
            header = f"[自动签到] {now_fzu().strftime('%H:%M:%S')} 第 {attempt} 次尝试"
            if on_status:
                on_status(header)
            append_log(header + "\n")
            ok, output = run_signin_once(cfg, ask_sms=ask_sms)
            append_log(output.rstrip() + "\n")
            if on_status:
                on_status(output.strip().splitlines()[-1] if output.strip() else header)

        if ok or is_success_text(output):
            mark_today_done("auto")
            append_log("[自动签到] 完成\n")
            if on_status:
                on_status("签到完成")
            notify_signin("success", output, str(cfg.get("address") or ""))
            return 0
        notify_signin("failure", output)
        if is_permanent_failure(output):
            append_log("[自动签到] 遇到不可自动恢复的错误，停止重试\n")
            if on_status:
                on_status("遇到无法自动恢复的错误，已停止")
            return 1

        remaining = (deadline - now_fzu()).total_seconds()
        if remaining <= 0:
            append_log("[自动签到] 已到截止时间，今晚不再重试\n")
            if on_status:
                on_status("已到 23:59，今晚不再重试")
            return 1

        sleep_for = min(delay, max(1, int(remaining)))
        append_log(f"[自动签到] 失败，{sleep_for} 秒后重试（等待期间若手动签到成功会立刻停止）\n")
        if on_status:
            on_status(f"失败，{sleep_for} 秒后重试")
        if wait_or_done(sleep_for):
            append_log("[自动签到] 今日已由其他方式完成，停止重试\n")
            if on_status:
                on_status("今日已签到，停止重试")
            return 0
        delay = min(int(delay * 1.5), MAX_DELAY_SEC)


def run_target() -> tuple[str, str, str]:
    if getattr(sys, "frozen", False):
        execute = sys.executable
        argument = "--run"
        workdir = str(Path(sys.executable).resolve().parent)
    else:
        execute = sys.executable
        argument = f'"{Path(__file__).resolve()}" --run'
        workdir = str(app_dir())
    return execute, argument, workdir


def ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def register_task(hour: int, minute: int) -> None:
    execute, argument, workdir = run_target()
    at = f"{hour:02d}:{minute:02d}"
    start_min = hour * 60 + minute
    end_min = STOP_HOUR * 60 + STOP_MINUTE
    limit_hours = max(1, (max(end_min - start_min, 30) + 59) // 60)
    names = list(OLD_TASK_NAMES)
    remove = "; ".join(
        f"Unregister-ScheduledTask -TaskName {ps_quote(n)} -Confirm:$false -ErrorAction SilentlyContinue"
        for n in names
    )
    script = f"""
$ErrorActionPreference = 'Stop'
{remove}
$action = New-ScheduledTaskAction -Execute {ps_quote(execute)} -Argument {ps_quote(argument)} -WorkingDirectory {ps_quote(workdir)}
$trigger = New-ScheduledTaskTrigger -Daily -At {at}
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours {limit_hours}) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName {ps_quote(TASK_NAME)} -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
"""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"创建计划任务失败: {detail}")


def unregister_task() -> None:
    for name in OLD_TASK_NAMES:
        subprocess.run(
            ["schtasks", "/Delete", "/TN", name, "/F"],
            capture_output=True,
            text=True,
        )


def task_exists() -> bool:
    proc = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def parse_form(values: dict) -> dict:
    username = values["username"].strip()
    password = values["password"]
    address = values["address"].strip()
    if not username:
        raise ValueError("请填写学号")
    if not password:
        raise ValueError("请填写密码")
    if not address:
        raise ValueError("请填写签到地址")
    hour = int(float(str(values["hour"]).strip() or "0"))
    minute = int(float(str(values["minute"]).strip() or "0"))
    if not 0 <= hour <= 23:
        raise ValueError("小时必须在 0-23 之间")
    if not 0 <= minute <= 59:
        raise ValueError("分钟必须在 0-59 之间")
    lon = float(values["lon"])
    lat = float(values["lat"])
    if not -180 <= lon <= 180:
        raise ValueError("经度必须在 -180 到 180 之间")
    if not -90 <= lat <= 90:
        raise ValueError("纬度必须在 -90 到 90 之间")
    return {
        "username": username,
        "password": password,
        "hour": hour,
        "minute": minute,
        "lon": lon,
        "lat": lat,
        "address": address,
        "sendkey": _checked_sendkey(values.get("sendkey")),
    }


def _checked_sendkey(raw: str) -> str:
    sendkey = str(raw or "").strip()
    if sendkey and not (sendkey.startswith("SCT") or sendkey.startswith("sctp")):
        raise ValueError("SendKey 应以 SCT 开头")
    return sendkey


OFF_CAMPUS_MARKERS = (
    "短信",
    "验证码",
    "校外",
    "统一认证拒绝",
    "图形验证码",
    "二次验证",
    "HTTP 401",
)
ATRUST_HINT = (
    "可能没有连上校内网。请打开 aTrust 并登录，服务器地址填 vpn2.fzu.edu.cn。\n\n"
    "还没安装的话，用浏览器打开 https://vpn2.fzu.edu.cn/ ，登录后点「立即下载」。"
)


def push_state_path(dt: datetime | None = None) -> Path:
    day = (dt or now_fzu()).strftime("%Y-%m-%d")
    return data_dir() / f"push-{day}.json"


def load_push_state() -> dict:
    path = push_state_path()
    if not path.is_file():
        return {"success": False, "failure": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"success": False, "failure": False}
    if not isinstance(data, dict):
        return {"success": False, "failure": False}
    return {"success": bool(data.get("success")), "failure": bool(data.get("failure"))}


def save_push_state(state: dict) -> None:
    push_state_path().write_text(json.dumps(state), encoding="utf-8")


def sc_send(sendkey: str, title: str, desp: str = "") -> None:
    key = sendkey.strip()
    title = " ".join(title.replace("\r", " ").splitlines()).strip() or "签到提醒"
    if key.startswith("sctp"):
        match = re.match(r"sctp(\d+)t", key)
        if not match:
            raise ValueError("SendKey 格式不对")
        url = f"https://{match.group(1)}.push.ft07.com/send/{key}.send"
    else:
        url = f"https://sctapi.ftqq.com/{key}.send"
    import requests

    try:
        response = requests.post(
            url,
            json={"title": title, "desp": desp},
            timeout=15,
        )
        data = response.json()
    except Exception as exc:
        text = str(exc).replace(key, "***")
        raise RuntimeError(text) from None
    if not isinstance(data, dict) or data.get("code") != 0:
        message = ""
        if isinstance(data, dict):
            message = str(data.get("message") or data.get("msg") or "")
        raise RuntimeError(message or "微信推送没有成功")


def notify_signin(kind: str, detail: str, address: str = "") -> None:
    cfg = load_config()
    key = str(cfg.get("sendkey") or "").strip()
    if not key:
        return
    state = load_push_state()
    slot = "success" if kind == "success" else "failure"
    if state.get(slot):
        return
    if slot == "success":
        title = "签到成功"
        place = address or str(cfg.get("address") or "")
        desp = f"今晚签好啦。\n\n时间：{now_fzu().strftime('%H:%M')}"
        if place:
            desp += f"\n\n地点：{place}"
    else:
        title = "签到还没成功"
        reason = " ".join(str(detail or "没有签上").split())
        if len(reason) > 300:
            reason = reason[:300] + "…"
        desp = reason or "没有签上"
        if any(marker in str(detail or "") for marker in OFF_CAMPUS_MARKERS):
            desp += "\n\n" + ATRUST_HINT
    try:
        sc_send(key, title, desp)
    except Exception as exc:
        append_log(f"[微信] 推送失败：{exc}\n")
        return
    state[slot] = True
    save_push_state(state)
    append_log(f"[微信] 已推送：{title}\n")


SCT_SIGNIN_URL = "https://sctapi.ftqq.com/user/signin"
SCT_CHECK_URL = "https://sctapi.ftqq.com/sso/check"
SCT_KEYS_URL = "https://sctapi.ftqq.com/appkey/list"


def _find_sendkey(obj) -> str:
    if isinstance(obj, dict):
        for key in ("sendkey", "send_key"):
            value = obj.get(key)
            if isinstance(value, str) and (value.startswith("SCT") or value.startswith("sctp")):
                return value
        for value in obj.values():
            found = _find_sendkey(value)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_sendkey(item)
            if found:
                return found
    return ""


def fetch_login_qr() -> tuple[str, str]:
    """取 Server酱 当前这一轮微信登录码。返回图片 data URL 和这一轮的临时 token。"""
    import requests

    resp = requests.get(SCT_SIGNIN_URL, timeout=20)
    resp.raise_for_status()
    data = (resp.json() or {}).get("data") or {}
    qr_url = str(data.get("qr_url") or "")
    token = str(data.get("token") or "")
    if not qr_url or not token:
        raise RuntimeError("没有拿到登录二维码，请稍后再试")
    img = requests.get(qr_url, timeout=20)
    img.raise_for_status()
    if not img.content:
        raise RuntimeError("登录二维码是空的")
    mime = (img.headers.get("content-type") or "image/jpeg").split(";")[0].strip() or "image/jpeg"
    encoded = base64.b64encode(img.content).decode("ascii")
    return f"data:{mime};base64,{encoded}", token


def confirm_login_qr(token: str) -> str:
    """微信扫完并确认后返回 SendKey。还没扫时返回空字符串。"""
    import requests

    if not token:
        return ""
    resp = requests.post(SCT_CHECK_URL, data={"token": token}, timeout=20)
    body = resp.json() if resp.content else {}
    data = body.get("data") if isinstance(body, dict) else None
    user = {}
    if isinstance(data, dict):
        inner = data.get("result")
        user = inner if isinstance(inner, dict) else data
    if not user:
        return ""
    key = _find_sendkey(user)
    if key:
        return key
    if not user.get("level"):
        return ""
    listed = requests.post(SCT_KEYS_URL, data={"token": token}, timeout=20)
    listed_body = listed.json() if listed.content else {}
    return _find_sendkey(listed_body)


def ui_dir() -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "ui"


def launch_gui() -> None:
    import webview

    class Api:
        def __init__(self) -> None:
            self.window = None
            self._sms_deliver = None
            self._bind_token = ""

        def get_state(self) -> dict:
            cfg = load_config()
            return {
                "username": cfg["username"],
                "password": cfg["password"],
                "hour": int(cfg["hour"]),
                "minute": f"{int(cfg['minute']):02d}",
                "lon": cfg["lon"],
                "lat": cfg["lat"],
                "address": cfg["address"],
                "sendkey": cfg.get("sendkey") or "",
                "task": task_exists(),
                "version": APP_VERSION,
            }

        def save(self, values: dict) -> dict:
            parsed = parse_form(values)
            save_config(parsed)
            register_task(parsed["hour"], parsed["minute"])
            return {
                "ok": True,
                "message": f"已保存，每天 {parsed['hour']:02d}:{parsed['minute']:02d} 自动签到",
            }

        def test_sign(self, values: dict) -> dict:
            parsed = parse_form(values)
            save_config(parsed)
            ok, output = run_signin_once(parsed, ask_sms=self.ask_sms)
            append_log(f"\n===== {now_fzu().isoformat()} 手动试签 =====\n{output}\n")
            success = ok or is_success_text(output)
            if success:
                mark_today_done("manual")
                notify_signin("success", output, str(parsed["address"]))
            else:
                notify_signin("failure", output)
            summary = output.strip().splitlines()[-1] if output.strip() else "无输出"
            return {"ok": success, "message": summary}

        def cancel_task(self) -> dict:
            unregister_task()
            return {"ok": True, "message": "已取消计划任务，配置还留着"}

        def open_logs(self) -> dict:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(LOG_DIR))
            return {"ok": True, "message": "已打开日志目录"}

        def test_push(self, sendkey: str) -> dict:
            key = _checked_sendkey(sendkey)
            if not key:
                raise ValueError("先把 SendKey 填上")
            sc_send(key, "签到提醒试一下", "能看到这条，就说明微信绑好啦。")
            cfg = load_config()
            cfg["sendkey"] = key
            if cfg.get("username") and cfg.get("password"):
                save_config(cfg)
            return {"ok": True, "message": "测试消息已发出，去微信看看「方糖」"}

        def refresh_qr(self) -> dict:
            image, token = fetch_login_qr()
            self._bind_token = token
            return {"ok": True, "image": image}

        def confirm_scan(self) -> dict:
            key = confirm_login_qr(self._bind_token)
            if not key:
                return {"ok": False, "message": "还没扫上。用微信扫完，并在微信里点确认后再试。"}
            return {"ok": True, "sendkey": key, "message": "SendKey 已填好，记得点保存"}

        def ask_sms(self, phone: str, tip: str) -> str:
            box = {"code": ""}
            done = threading.Event()

            def deliver(code: str) -> None:
                box["code"] = (code or "").strip()
                done.set()

            self._sms_deliver = deliver
            if self.window is None:
                return ""
            try:
                self.window.evaluate_js(
                    "window.askSmsCode("
                    + json.dumps(phone)
                    + ","
                    + json.dumps(tip or "")
                    + ")"
                )
            except Exception:
                return ""
            done.wait(timeout=300)
            return box["code"]

        def submit_sms(self, code: str) -> dict:
            deliver = self._sms_deliver
            if deliver:
                deliver(code or "")
            return {"ok": True}

    page = ui_dir() / "index.html"
    if not page.is_file():
        raise FileNotFoundError(f"找不到界面文件: {page}")
    bridge = Api()
    window = webview.create_window(
        f"{APP_NAME} {APP_VERSION}",
        url=page.as_uri(),
        js_api=bridge,
        width=960,
        height=780,
        min_size=(860, 740),
        background_color="#FFFDF9",
        text_select=True,
    )
    bridge.window = window
    webview.start()


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--run", action="store_true", help="由计划任务调用：静默签到并重试到 23:59")
    args = parser.parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if args.run:
        try:
            return run_signin_with_retry()
        except Exception as exc:
            append_log(f"[错误] {exc}\n{traceback.format_exc()}\n")
            return 1

    launch_gui()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
