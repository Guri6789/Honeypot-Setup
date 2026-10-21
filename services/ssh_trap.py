"""
HoneyBank - SSH Trap
A fake SSH server that captures brute force credential attempts
Requires: pip install paramiko
"""

import socket
import threading
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko
from core.logger import log_ssh_attempt
from core.alerter import alert
from core.detector import track_brute_force, blacklist_ip
from config import SSH_TRAP_PORT, SSH_HOST_KEY

# ─── Generate host key if it doesn't exist ─────────────────────────────
os.makedirs(os.path.dirname(SSH_HOST_KEY), exist_ok=True)
if not os.path.exists(SSH_HOST_KEY):
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(SSH_HOST_KEY)
    print(f"[SSH] Generated new host key → {SSH_HOST_KEY}")

HOST_KEY = paramiko.RSAKey(filename=SSH_HOST_KEY)


class HoneypotSSHServer(paramiko.ServerInterface):
    """Fake SSH server implementation that rejects all auth but logs attempts."""

    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Called on every password auth attempt — log it and always reject."""
        log_entry = log_ssh_attempt(self.client_ip, username, password)

        brute = track_brute_force(self.client_ip, success=False)
        if brute.get("detected"):
            attack_data = {
                **log_entry,
                "attack_type": "BRUTE_FORCE",
                "endpoint": f"ssh:{SSH_TRAP_PORT}",
                "severity": brute.get("severity", "HIGH"),
                "extra": {"failed_attempts": brute.get("failed_attempts")}
            }
            alert(attack_data)

            # Blacklist after extreme brute force
            if brute.get("failed_attempts", 0) > 30:
                blacklist_ip(self.client_ip)

        # Always deny — this is a honeypot
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Log public key auth attempts too."""
        print(f"[SSH] Pubkey attempt — user={username} from {self.client_ip}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"


def handle_connection(client_socket: socket.socket, client_ip: str):
    """Handle a single SSH connection."""
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)

        # Fake SSH banner to look convincing
        transport.local_version = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2"

        server = HoneypotSSHServer(client_ip)
        transport.start_server(server=server)

        # Wait briefly then close — never actually grant access
        chan = transport.accept(timeout=20)
        if chan:
            chan.close()

    except Exception as e:
        print(f"[SSH] Connection error from {client_ip}: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        client_socket.close()


def start_ssh_trap():
    """Start the fake SSH server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", SSH_TRAP_PORT))
    server_socket.listen(10)

    print(f"[*] SSH Trap listening on port {SSH_TRAP_PORT}")

    while True:
        try:
            client_sock, (client_ip, client_port) = server_socket.accept()
            print(f"[SSH] Connection from {client_ip}:{client_port}")
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, client_ip),
                daemon=True
            )
            t.start()
        except Exception as e:
            print(f"[SSH] Accept error: {e}")


if __name__ == "__main__":
    start_ssh_trap()
