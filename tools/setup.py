"""为新部署生成独立配置；不覆盖现有密钥、数据库或登录密码。"""
import argparse
import getpass
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="https://localhost:8443")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    origin = urlsplit(args.origin)
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path or origin.query or origin.fragment
            or not re.fullmatch(r"[A-Za-z0-9.:-]+", origin.netloc)):
        parser.error("--origin 必须为 HTTPS 根地址，例如 https://login.example.com:8443")
    if not 1 <= args.port <= 65535:
        parser.error("--port 必须为 1–65535")
    try:
        ipaddress.ip_address(args.bind)
    except ValueError:
        parser.error("--bind 必须是监听 IP 地址")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", args.username):
        parser.error("用户名仅允许字母、数字、下划线、点和短横线")
    if (root / ".env").exists() or (root / "private").exists():
        parser.error("已有 .env 或 private 目录；请保留现有部署材料，脚本不会覆盖")
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("请先安装 OpenSSL")
    password = getpass.getpass("网页登录密码（至少 12 位）：")
    if len(password) < 12 or any(ord(c) < 32 or ord(c) == 127 for c in password):
        parser.error("密码至少 12 位，且不能包含控制字符")
    if password != getpass.getpass("再次输入密码："):
        parser.error("两次密码不一致")
    # 密码只经 stdin 传入，不出现在进程参数或终端输出中。
    hashed = subprocess.run([openssl, "passwd", "-apr1", "-stdin"], input=password + "\n",
                            text=True, capture_output=True, check=True).stdout.strip()
    private = root / "private"
    private.mkdir(mode=0o700)
    tls = private / "tls"
    tls.mkdir(mode=0o700)
    os.umask(0o077)
    (private / "access.htpasswd").write_text(args.username + ":" + hashed + "\n")
    # 容器内 UID 1000 需要读取密码摘要；父目录始终为 0700。
    (private / "access.htpasswd").chmod(0o644)
    try:
        ipaddress.ip_address(origin.hostname)
        san = "IP:" + origin.hostname
    except ValueError:
        san = "DNS:" + origin.hostname
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
                    "-keyout", str(tls / "key.pem"), "-out", str(tls / "cert.pem"),
                    "-subj", "/CN=" + origin.hostname, "-addext", "subjectAltName=" + san],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / ".env").write_text(
        f"PUBLIC_ORIGIN={args.origin}\nHTTPS_BIND={args.bind}\nHTTPS_PORT={args.port}\n"
        f"TOSUB2_CONSOLE_TOKEN={secrets.token_urlsafe(32)}\n"
        f"CRS_LOGIN_BRIDGE_KEY={secrets.token_urlsafe(32)}\n"
        "TOSUB2_DEFAULT_OPERATION_PROXY_ENABLED=0\nTOSUB2_OPERATION_PROXY_URL=\n"
        "TOSUB2_DYNAMIC_PROXY_EXTRACTION=0\n")
    print("配置已生成。运行 docker compose up -d --build 后访问 " + args.origin)
    print("已生成自签名证书；公网部署请替换 private/tls 下的证书与私钥。")


if __name__ == "__main__":
    main()
