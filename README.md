# 福大晚点名自动签到

福州大学晚点名签到助手。窗口里填学号、密码和时间，到点自动签；也可以立刻试签一次。

当前版本 **1.1.0**，Windows 可执行文件在 [Releases](https://github.com/Champion31415926/fzu-auto-checkin/releases/tag/v1.1.0)。

## 1.1.0 更新公告

- 新增 地图选择签到位置 功能
- 新增 微信推送“签到成功”功能
- 更新 UI样式

## 使用

1. 从 [v1.1.0](https://github.com/Champion31415926/fzu-auto-checkin/releases/tag/v1.1.0) 下载 `fzu-auto-checkin-1.1.0.exe`。
2. 打开后填写学号、密码和签到时间，点「保存并创建计划任务」。
3. 需要微信提醒时，点「绑定微信」，扫码关注「方糖」，确认后 SendKey 会填回来，再保存一次。
4. 人在校外请先连上 aTrust，服务器填 `vpn2.fzu.edu.cn`。下载页：打开 https://vpn2.fzu.edu.cn/ ，登录后点「立即下载」。

计划任务记的是保存时的程序路径。换了新版本后，要用新程序再点一次「保存并创建计划任务」。

## 从源码运行

```bash
pip install -r requirements.txt
python app.py
```

账号和密码保存在本机 `%APPDATA%\FZUAttn\`，不要把 `.env` 或配置文件提交到仓库。
