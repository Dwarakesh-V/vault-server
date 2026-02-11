
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple

class SecurityManager:
    def __init__(self):
        # Stores failed attempts: ip_address -> (count, first_attempt_time)
        self.failed_attempts: Dict[str, Tuple[int, float]] = {}
        # Stores blocked IPs: ip_address -> unblock_time
        self.blocked_ips: Dict[str, float] = {}
        
        # Configuration
        self.MAX_ATTEMPTS = 5
        self.TIME_WINDOW = 300  # 5 minutes in seconds
        self.BLOCK_DURATION = 60  # 1 minute in seconds (for testing)

    def check_rate_limit(self, ip_address: str):
        """Check if IP is currently blocked"""
        current_time = time.time()
        
        # Check if IP is in blocked list
        if ip_address in self.blocked_ips:
            unblock_time = self.blocked_ips[ip_address]
            if current_time < unblock_time:
                raise ValueError(f"IP blocked due to too many failed attempts. Try again in {int(unblock_time - current_time)} seconds.")
            else:
                # Block expired
                del self.blocked_ips[ip_address]
                if ip_address in self.failed_attempts:
                    del self.failed_attempts[ip_address]

    def record_failed_attempt(self, ip_address: str, username: str = None):
        """Record a failed login attempt"""
        current_time = time.time()
        
        # Initialize or update failed attempts
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = (1, current_time)
        else:
            count, first_time = self.failed_attempts[ip_address]
            
            # Check if time window has passed, reset if so
            if current_time - first_time > self.TIME_WINDOW:
                self.failed_attempts[ip_address] = (1, current_time)
            else:
                # Increment count
                new_count = count + 1
                self.failed_attempts[ip_address] = (new_count, first_time)
                
                # Check if threshold reached
                if new_count >= self.MAX_ATTEMPTS:
                    self.blocked_ips[ip_address] = current_time + self.BLOCK_DURATION
                    print(f"SECURITY ALERT: Blocked IP {ip_address} after {new_count} failed attempts.")
                    if username:
                         print(f"Suspicious activity detected for user: {username}")

    def reset_attempts(self, ip_address: str):
        """Reset failed attempts on successful login"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]

security_manager = SecurityManager()
