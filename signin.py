#!/usr/bin/env python3
"""晚点名签到。"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import ssl
import string
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import requests

# ---------------------------------------------------------------- 常量
SSO_LOGIN = "https://sso.fzu.edu.cn/login"
SSO_SMS_URL = "https://sso.fzu.edu.cn/api/protected/sms/publicNoToken/sendSmsCode"
SSO_CHECK_SMS = "https://sso.fzu.edu.cn/api/protected/sms/checkToken"
YZSXG_OAUTH_CALLBACK = (
    "https://yzsxg.fzu.edu.cn/livecloud/project/fzu/attn/oauth2/callback.action"
)
ATTN_BASE = "https://yzsxg.fzu.edu.cn/livecloud/project/fzu/attn"
ATTN_KEY = b"apexinfoapexinfo"
FZU_TIMEZONE = timezone(timedelta(hours=8), name="Asia/Shanghai")

# 请求头
APP_UA = (
    "Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Mobile/15E148 appId/cn.edu.fzu.fdxypa "
    "appScheme/kysk-fdxy-app hengfeng/fdxyappzs appType/2"
)
SSO_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# ---------------------------------------------------------------- 请求工具(带重试 + TLS1.2 降级)
# SSO 服务器偶发对 TLS1.3/部分握手直接断开(SSLEOFError), 自动重试并在必要时降级 TLS1.2


def make_adapter(tls12_only=False):
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context

    class _A(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = create_urllib3_context()
            if tls12_only:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            kwargs["ssl_context"] = ctx
            return super().init_poolmanager(*args, **kwargs)

    return _A()


def _new_session(tls12):
    s = requests.Session()
    s.mount("https://", make_adapter(tls12_only=tls12))
    return s


S = _new_session(False)  # 全局会话(保持 cookie)


def reset_session() -> None:
    """每次独立签到前重置会话，避免重试时沿用过期 cookie。"""
    global S
    S = _new_session(False)


def _display_url(url: str) -> str:
    """日志中仅显示主机和路径，避免泄露 OAuth code/token 或加密参数。"""
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def req(method, url, max_retries=3, **kw):
    """带自动重试的请求;连续失败后切换 TLS1.2 再试, 仍失败抛最后一个异常"""
    global S
    if max_retries < 1:
        raise ValueError("max_retries 必须至少为 1")
    method = method.upper()
    kw.setdefault("timeout", 20)
    last = None
    for attempt in range(max_retries):
        try:
            return S.request(method, url, **kw)
        except (
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        ) as e:
            last = e
            will_retry = attempt + 1 < max_retries
            label = "重试" if will_retry else "失败"
            print(
                f"[{label}] {method} {_display_url(url)} 第{attempt + 1}次失败: {type(e).__name__}"
            )
            if attempt == 1 and will_retry:  # 第二次失败后切 TLS1.2
                cookies = S.cookies.copy()
                S = _new_session(tls12=True)
                S.cookies.update(cookies)
            if will_retry:
                time.sleep(1.5 * (attempt + 1))
    raise last


# ---------------------------------------------------------------- 加密工具
def aes_ecb_encrypt_b64(raw: str, key_b64: str) -> str:
    """SSO 密码加密:AES-128-ECB + PKCS7 + base64"""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    try:
        key = base64.b64decode(key_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("SSO 返回了无效的 Base64 加密密钥") from exc
    if len(key) not in (16, 24, 32):
        raise RuntimeError(f"SSO 返回了无效的 AES 密钥长度: {len(key)}")
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(raw.encode("utf-8"), AES.block_size))
    return base64.b64encode(ct).decode()


def aes_cbc_encrypt_b64(obj) -> str:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher = AES.new(ATTN_KEY, AES.MODE_CBC, iv=ATTN_KEY)
    return base64.b64encode(cipher.encrypt(pad(data, AES.block_size))).decode()


def gen_csrf():
    chars = string.ascii_letters + string.digits
    key = "".join(secrets.choice(chars) for _ in range(32))
    b64 = base64.b64encode(key.encode()).decode()
    half = len(b64) // 2
    val = b64[:half] + b64 + b64[half:]
    return key, hashlib.md5(val.encode()).hexdigest()


# ---------------------------------------------------------------- Step1: SSO 登录
def sso_login(username: str, password: str, ask_sms=None) -> str:
    """返回 SOURCEID_TGC cookie;若触发短信两步验证,通过 ask_sms 或终端输入验证码"""
    r = req("GET", SSO_LOGIN, headers={"User-Agent": SSO_UA})
    r.raise_for_status()
    html = r.text
    m_key = re.search(r'<p id="login-croypto">(.*?)</p>', html)
    m_flow = re.search(r'<p id="login-page-flowkey">(.*?)</p>', html)
    if not m_key or not m_flow:
        raise RuntimeError("无法从登录页提取密钥/flowkey")
    croypto, execution = m_key.group(1), m_flow.group(1)
    has_session = any(c.name == "SESSION" for c in S.cookies)
    print(
        f"[登录] 已获取加密密钥与执行流, SESSION={'已设置' if has_session else '未设置'}"
    )

    def submit_login(form: dict) -> requests.Response:
        # 福大 SSO 在密码错误、短信二次验证、验证码时都可能返回 401。
        # 必须先读正文，不能 raise_for_status 直接丢掉原因。
        return req(
            "POST",
            SSO_LOGIN,
            max_retries=1,
            data=form,
            headers={
                "User-Agent": SSO_UA,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            allow_redirects=False,
        )

    def html_p(text: str, pid: str) -> str:
        match = re.search(rf'<p id="{re.escape(pid)}">(.*?)</p>', text or "", re.S)
        return match.group(1).strip() if match else ""

    def is_sms_challenge(response: requests.Response) -> bool:
        return 'current-login-type">smsLogin' in (response.text or "")

    form = {
        "username": username,
        "type": "UsernamePassword",
        "_eventId": "submit",
        "geolocation": "",
        "execution": execution,
        "captcha_code": "",
        "croypto": croypto,
        "password": aes_ecb_encrypt_b64(password, croypto),
        "captcha_payload": aes_ecb_encrypt_b64("{}", croypto),
    }
    resp = submit_login(form)

    # 两步验证(非校内 IP 常见；可能是 200 也可能是 401)
    if is_sms_challenge(resp):
        phone = re.search(r'<p id="phone-number">(.*?)</p>', resp.text)
        tip = re.search(r'<p id="second-auth-tip">(.*?)</p>', resp.text)
        if not phone or not phone.group(1).strip():
            raise RuntimeError("需要短信两步验证，但登录页未提供手机号")
        phone_number = phone.group(1).strip()
        if ask_sms is None and not sys.stdin.isatty():
            raise RuntimeError(
                "需要短信两步验证，当前可能不在校园网。自动任务不会再发验证码，连上 aTrust 后再试。"
            )
        print(f"[两步验证] 手机号 {phone_number} - {tip.group(1) if tip else ''}")
        ck, cv = gen_csrf()
        sms_resp = req(
            "POST",
            SSO_SMS_URL,
            max_retries=1,
            json={"businessNo": "0008", "phone": phone_number},
            headers={"Csrf-Key": ck, "Csrf-Value": cv, "User-Agent": SSO_UA},
        )
        sms_resp.raise_for_status()
        sms = sms_resp.json()
        if not isinstance(sms, dict):
            raise RuntimeError("短信发送接口返回了无效数据")
        print(f"[短信] 发送结果: {sms.get('code')} {sms.get('msg') or ''}")
        if ask_sms is not None:
            code = (ask_sms(phone_number, tip.group(1) if tip else "") or "").strip()
        elif sys.stdin.isatty():
            code = input("请输入收到的短信验证码: ").strip()
        else:
            raise RuntimeError("需要短信两步验证，请打开窗口程序完成一次登录，或在校园网环境下使用")
        if not code:
            raise RuntimeError("短信验证码不能为空")
        ck2, cv2 = gen_csrf()
        chk_resp = req(
            "POST",
            SSO_CHECK_SMS,
            max_retries=1,
            json={
                "phone": phone_number,
                "token": code,
                "delete": "false",
                "trustDevice": "false",
            },
            headers={"Csrf-Key": ck2, "Csrf-Value": cv2, "User-Agent": SSO_UA},
        )
        chk_resp.raise_for_status()
        chk = chk_resp.json()
        if not isinstance(chk, dict):
            raise RuntimeError("验证码校验接口返回了无效数据")
        if chk.get("code") != 200:
            raise RuntimeError(f"验证码校验失败: {chk}")
        resp = submit_login(
            {
                "username": username,
                "password": code,
                "type": "smsLogin",
                "_eventId": "submit",
                "geolocation": "",
                "execution": execution,
                "captcha_code": "",
                "trustDevice": "false",
            }
        )

    if resp.status_code >= 400 and not is_sms_challenge(resp):
        err_code = html_p(resp.text, "login-error-code")
        captcha = html_p(resp.text, "captcha-url")
        detail = f"HTTP {resp.status_code}"
        if err_code:
            detail += f" {err_code}"
        if captcha:
            detail += " 需要图形验证码"
        raise RuntimeError(
            f"统一认证拒绝登录 ({detail})。"
            "窗口里改过密码后必须保存；计划任务不会用未保存的新密码。"
        )

    tgc = next((c.value for c in S.cookies if c.name == "SOURCEID_TGC"), None)
    if not tgc:
        tgc = resp.cookies.get("SOURCEID_TGC")
    if not tgc:
        raise RuntimeError(
            "未能拿到登录票据，可能是已保存的密码仍是旧的、需要验证码或二次验证"
        )
    print("[登录] SSO 登录成功")
    return f"SOURCEID_TGC={tgc}"


# ---------------------------------------------------------------- Step2: 换 yzsxg token
def _extract_token(resp) -> str:
    """从响应中提取 token:优先 Location, 其次 JSON body/纯文本"""
    loc = resp.headers.get("Location") or ""
    m = re.search(r"[?&]token=([^&#]+)", loc)
    if m:
        return urllib.parse.unquote(m.group(1))
    m = re.search(r'"token"\s*:\s*"([^"]+)"', resp.text)
    if m:
        return m.group(1)
    try:
        body = resp.json()
        if isinstance(body, dict):
            t = body.get("token") or (body.get("data") or {}).get("token")
            if t:
                return str(t)
    except (requests.exceptions.JSONDecodeError, AttributeError, TypeError):
        pass
    return ""


def _install_sso_cookie(cookie_header: str) -> None:
    """只安装 SSO TGC，并让 requests 按域名规则决定何时发送。"""
    match = re.search(r"(?:^|;\s*)SOURCEID_TGC=([^;]+)", cookie_header)
    if not match or not match.group(1).strip():
        raise ValueError("--sso-cookie 必须包含 SOURCEID_TGC=... 格式的有效值")
    S.cookies.set(
        "SOURCEID_TGC",
        match.group(1).strip(),
        domain="sso.fzu.edu.cn",
        path="/",
        secure=True,
    )


def _validated_redirect(current_url: str, location: str) -> str:
    """仅允许 OAuth 链重定向到福大 HTTPS 域名。"""
    target = urllib.parse.urljoin(current_url, location)
    parsed = urllib.parse.urlsplit(target)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (
        host == "fzu.edu.cn" or host.endswith(".fzu.edu.cn")
    ):
        raise RuntimeError(f"OAuth 返回了不受信任的重定向目标: {_display_url(target)}")
    return target


def get_attn_token(sso_cookie: str, debug: bool = False) -> str:
    """带 SSO cookie 走 OAuth2 重定向链, token 出现即提取(任意一跳)"""
    service = urllib.parse.quote(YZSXG_OAUTH_CALLBACK, safe="")
    url = f"{SSO_LOGIN}?service={service}"
    _install_sso_cookie(sso_cookie)
    resp = req("GET", url, headers={"User-Agent": APP_UA}, allow_redirects=False)
    resp.raise_for_status()
    if debug:
        print(f"[OAuth] 1) {resp.status_code} {_display_url(resp.url)}")
        if resp.headers.get("Location"):
            print(
                f"         -> {_display_url(urllib.parse.urljoin(resp.url, resp.headers['Location']))}"
            )

    for i in range(10):
        tok = _extract_token(resp)
        if tok:
            return tok
        nxt = resp.headers.get("Location")
        if not nxt:
            break
        nxt = _validated_redirect(resp.url, nxt)
        resp = req("GET", nxt, headers={"User-Agent": APP_UA}, allow_redirects=False)
        resp.raise_for_status()
        if debug:
            print(f"[OAuth] {i + 2}) {resp.status_code} {_display_url(resp.url)}")
            if resp.headers.get("Location"):
                print(
                    f"         -> {_display_url(urllib.parse.urljoin(resp.url, resp.headers['Location']))}"
                )

    tok = _extract_token(resp)
    if tok:
        return tok
    location = resp.headers.get("Location", "")
    location_info = (
        _display_url(urllib.parse.urljoin(resp.url, location)) if location else "无"
    )
    raise RuntimeError(
        f"未能从 OAuth 重定向中提取 token。最后响应: {resp.status_code} "
        f"{_display_url(resp.url)} Location={location_info}"
    )


# ---------------------------------------------------------------- Step3: 签到
def attn_api(
    action: str,
    params_obj: dict,
    token: str,
    method: str = "GET",
    double_encode: bool = False,
):
    enc = aes_cbc_encrypt_b64(params_obj)
    q = urllib.parse.quote(enc, safe="")
    if double_encode:
        q = urllib.parse.quote(q, safe="")
    url = f"{ATTN_BASE}/{action}?param={q}"
    headers = {"token": token, "User-Agent": APP_UA}
    retries = 1 if action == "clockIn.action" else 3
    if method == "GET":
        r = req("GET", url, headers=headers, max_retries=retries)
    elif method == "POST":
        r = req("POST", url, json={}, headers=headers, max_retries=retries)
    else:
        raise ValueError(f"不支持的 HTTP 方法: {method}")
    r.raise_for_status()
    try:
        body = r.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise RuntimeError(
            f"{action} 返回了非 JSON 响应(status={r.status_code}, "
            f"content-type={r.headers.get('Content-Type', '未知')})"
        ) from exc
    if not isinstance(body, dict):
        raise TypeError(f"{action} 返回了无效的数据结构")
    return body


def _strip_text(value) -> str:
    return str(value or "").strip()


def _normalize_init_data(raw: dict) -> dict:
    """把当前 yzsxg init 嵌套字段转成脚本使用的扁平结构。"""
    if not isinstance(raw, dict):
        return {}
    if "clockWay" in raw or "userName" in raw:
        return raw

    params = raw.get("paramsData") or {}
    user = raw.get("userData") or {}
    status = raw.get("statusData") or {}
    school = raw.get("schoolData") or []
    school0 = school[0] if isinstance(school, list) and school else {}
    if not isinstance(params, dict):
        params = {}
    if not isinstance(user, dict):
        user = {}
    if not isinstance(status, dict):
        status = {}
    if not isinstance(school0, dict):
        school0 = {}

    check_in = _strip_text(user.get("FCheckInTime"))
    state = _strip_text(user.get("FState") or status.get("status")).upper()
    already = state == "SUCCESS" or "已签到" in check_in
    return {
        "userName": user.get("FName"),
        "userClass": user.get("FClass"),
        "clockWay": user.get("FWay"),
        "clockName": _strip_text(params.get("FTips")) or "晚点名",
        "clockStartTime": _strip_text(params.get("FStartTime")),
        "clockEndTime": _strip_text(params.get("FEndTime")),
        "lateTime": _strip_text(params.get("FLateTime")) or "23:00",
        "clockSuccess": already,
        "clockInTime": check_in,
        "clockInLocation": user.get("FActualLocation"),
        "schoolPosition": school0.get("FPosition") or "{}",
        "collUnit": user.get("FCollUnit") or "",
        "defaultCampus": _strip_text(user.get("FDefaultCampus") or user.get("FCampus")),
    }


def do_signin(
    token: str,
    lon: float,
    lat: float,
    address: str,
    debug: bool = False,
    double_encode: bool = False,
):
    def api(action: str, params_obj: dict, method: str = "GET"):
        return attn_api(action, params_obj, token, method, double_encode)

    init = api("init.action", {}, method="POST")
    if debug:
        print("[init] " + json.dumps(init, ensure_ascii=False)[:800])
    if not init.get("success") or init.get("code") != 1:
        raise RuntimeError(f"init 失败: {json.dumps(init, ensure_ascii=False)}")
    d = init.get("data", {}) or {}
    if not isinstance(d, dict):
        raise TypeError("init 返回的 data 不是对象")
    d = _normalize_init_data(d)
    print(f"用户   : {d.get('userName')} {d.get('userClass')}")
    way_name = {1: "校内", 2: "外勤", 3: "无需签到"}.get(d.get("clockWay"), "未知")
    print(
        f"签到项 : {d.get('clockName')} 方式={way_name}"
        f" 时段 {d.get('clockStartTime')}-{d.get('clockEndTime')}"
    )
    if d.get("clockSuccess"):
        print(f"[跳过] 今日已签到 {d.get('clockInTime')} @ {d.get('clockInLocation')}")
        return
    if d.get("clockWay") == 3:
        print("[跳过] 今日无需签到")
        return

    # 迟到判断(服务器时间 vs lateTime)
    try:
        ts = api("currentTimestamp.action", {})
        now_ms = int(ts["data"]["timestamp"])
    except (
        KeyError,
        TypeError,
        ValueError,
        requests.RequestException,
        RuntimeError,
    ) as exc:
        print(f"[警告] 获取服务器时间失败({exc}), 使用本机时间")
        now_ms = int(time.time() * 1000)
    late_match = re.fullmatch(r"(\d{1,2}):(\d{2})", str(d.get("lateTime") or "23:00"))
    if not late_match:
        raise RuntimeError(f"lateTime 格式无效: {d.get('lateTime')!r}")
    late_hour, late_minute = map(int, late_match.groups())
    if not (0 <= late_hour <= 23 and 0 <= late_minute <= 59):
        raise RuntimeError(f"lateTime 超出有效范围: {d.get('lateTime')!r}")
    now = datetime.fromtimestamp(now_ms / 1000, tz=FZU_TIMEZONE)
    is_late = int(now.hour * 60 + now.minute > late_hour * 60 + late_minute)

    campus = ""
    try:
        chk = api(
            "check.action",
            {
                "mapType": "amap",
                "longitude": lon,
                "latitude": lat,
                "range": d.get("schoolPosition") or "{}",
            },
        )
        arr = chk.get("data") or []
        if isinstance(arr, list) and arr:
            campus = str(arr[0].get("id", ""))
    except (
        requests.RequestException,
        RuntimeError,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        AttributeError,
    ) as e:
        print(f"[警告] check 失败({e}), campus 置空")
    if not campus:
        campus = d.get("defaultCampus") or ""

    payload = {
        "campus": campus,
        "lon": lon,
        "lat": lat,
        "startTime": d.get("clockStartTime"),
        "endTime": d.get("clockEndTime"),
        "actualLocation": address,
        "caIsNo": "0",
        "collUnit": d.get("collUnit") or "",
        "way": d.get("clockWay"),
        "isLate": is_late,
    }
    print(f"[签到] {json.dumps(payload, ensure_ascii=False)}")
    ret = api("clockIn.action", payload)
    if ret.get("success") and ret.get("code") == 1:
        print(f"[成功] 签到完成: {json.dumps(ret.get('data'), ensure_ascii=False)}")
        return
    msg = str(ret.get("msg") or "")
    if "请勿重复打卡" in msg or "已签到" in msg:
        print(f"[跳过] {msg}")
        return
    raise RuntimeError(f"签到失败: {json.dumps(ret, ensure_ascii=False)}")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="智汇福大晚点名自动签到")
    ap.add_argument("--username", help="学号(未提供 --password 时将安全地提示输入)")
    ap.add_argument(
        "--password", help="统一身份认证密码(不推荐: 会留在 shell 历史和进程参数中)"
    )
    ap.add_argument("--token", help="直接使用已有签到 token, 跳过登录")
    ap.add_argument(
        "--sso-cookie", help="已有 SSO cookie(SOURCEID_TGC=xxx), 跳过账号密码"
    )
    ap.add_argument("--lon", type=float, default=119.188916)
    ap.add_argument("--lat", type=float, default=26.058772)
    ap.add_argument("--address", default="旗山校区 学府北路10-165号")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument(
        "--double-encode", action="store_true", help="param 双 URL 编码(异常时尝试)"
    )
    args = ap.parse_args()

    if not -180 <= args.lon <= 180:
        ap.error("--lon 必须在 -180 到 180 之间")
    if not -90 <= args.lat <= 90:
        ap.error("--lat 必须在 -90 到 90 之间")
    if not args.address.strip():
        ap.error("--address 不能为空")

    token = args.token.strip() if args.token else None
    if not token:
        sso_cookie = args.sso_cookie
        if not sso_cookie:
            username = (args.username or os.environ.get("FZU_USERNAME") or "").strip()
            if not username:
                ap.error("请提供 --token, 或 --username, 或 --sso-cookie")
            password = args.password or os.environ.get("FZU_PASSWORD")
            if not password:
                if sys.stdin.isatty():
                    password = getpass.getpass("统一身份认证密码: ")
                else:
                    ap.error("密码不能为空(非交互环境请设置 FZU_PASSWORD 或使用 --password)")
            if not password:
                ap.error("密码不能为空")
            sso_cookie = sso_login(username, password)
        print("[换token] 正在换取签到系统 token ...")
        token = get_attn_token(sso_cookie, debug=args.debug)
        print(f"[换token] 成功: {token[:12]}...{token[-6:]}")
    do_signin(
        token,
        args.lon,
        args.lat,
        args.address,
        debug=args.debug,
        double_encode=args.double_encode,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
    except Exception as e:  # noqa: BLE001 - CLI 入口需将所有未处理异常转成简洁错误信息
        print(f"\n[错误] {e}")
        sys.exit(1)
