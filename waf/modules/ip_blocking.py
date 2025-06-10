from datetime import datetime, timedelta
import threading
import time
from typing import Dict, Any


class IPBlocker:
    def __init__(self, enabled: bool = True, block_duration: int = 24, cleanup_interval: int = 300):
        self.enabled = enabled
        self.ip_blacklist: Dict[str, datetime] = {}
        self.BLOCK_DURATION = timedelta(hours=block_duration)
        self.cleanup_interval = cleanup_interval
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        def cleanup():
            while True:
                time.sleep(self.cleanup_interval)
                now = datetime.now()
                self.ip_blacklist = {ip: expire_time for ip, expire_time in self.ip_blacklist.items()
                                     if expire_time > now}

        threading.Thread(target=cleanup, daemon=True).start()

    def block_ip(self, ip: str):
        if self.enabled:
            self.ip_blacklist[ip] = datetime.now() + self.BLOCK_DURATION

    def unblock_ip(self, ip: str):
        if ip in self.ip_blacklist:
            del self.ip_blacklist[ip]

    def is_blocked(self, ip: str) -> bool:
        if not self.enabled:
            return False
        expire_time = self.ip_blacklist.get(ip)
        if expire_time is None:
            return False
        if datetime.now() < expire_time:
            return True
        return False

    def get_blocked_ips(self) -> Dict[str, str]:
        return {ip: expire_time.isoformat() for ip, expire_time in self.ip_blacklist.items()}

    def get_config(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'block_duration_hours': self.BLOCK_DURATION.total_seconds() // 3600,
            'cleanup_interval_seconds': self.cleanup_interval
        }