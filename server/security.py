
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple


class SecurityManager:
    """
    Tracks failed login attempts per IP address and automatically blocks
    IPs that exceed the allowed failure threshold within a time window.

    This protects against:
      - Brute-force attacks (repeatedly guessing passwords)
      - Credential stuffing (trying leaked username/password combos)
      - Bot-driven attacks (automated rapid-fire login attempts)

    All state is stored in-memory, so it resets on server restart.
    For production, this should be backed by Redis or a database.
    """

    def __init__(self):
        # Dictionary that maps each IP address to a tuple of:
        #   (failure_count, timestamp_of_first_failure_in_current_window)
        # Example: {"192.168.1.1": (3, 1708500000.0)}
        self.failed_attempts: Dict[str, Tuple[int, float]] = {}

        # Dictionary that maps blocked IP addresses to the Unix timestamp
        # at which the block expires and login attempts are allowed again.
        # Example: {"192.168.1.1": 1708500060.0}
        self.blocked_ips: Dict[str, float] = {}

        # ── Tunable configuration ──────────────────────────────────────────
        self.MAX_ATTEMPTS  = 5    # number of failures before the IP is blocked
        self.TIME_WINDOW   = 300  # sliding window in seconds (5 minutes)
                                  # failures older than this are ignored / reset
        self.BLOCK_DURATION = 60  # how long (seconds) a blocked IP must wait
                                  # set to 60s for testing; use 900s in production

    # ──────────────────────────────────────────────────────────────────────────
    def check_rate_limit(self, ip_address: str):
        """
        Check whether the given IP is currently blocked due to too many
        failed login attempts.

        Called BEFORE processing a login request so that blocked IPs are
        rejected immediately without touching the database.

        Raises ValueError with a human-readable message (including remaining
        wait time in seconds) if the IP is blocked.
        Does nothing if the IP is clean or if its block has expired.
        """
        current_time = time.time()   # current Unix timestamp (float, seconds)

        # Check if this IP address is in our blocked list
        if ip_address in self.blocked_ips:
            unblock_time = self.blocked_ips[ip_address]   # time when block lifts

            if current_time < unblock_time:
                # Block is still active → calculate remaining seconds and reject
                remaining = int(unblock_time - current_time)
                raise ValueError(
                    f"IP blocked due to too many failed attempts. "
                    f"Try again in {remaining} seconds."
                )
            else:
                # Block duration has elapsed → remove the block so the IP can try again
                del self.blocked_ips[ip_address]

                # Also clear the failure history so the counter starts fresh
                if ip_address in self.failed_attempts:
                    del self.failed_attempts[ip_address]

    # ──────────────────────────────────────────────────────────────────────────
    def record_failed_attempt(self, ip_address: str, username: str = None):
        """
        Record one failed login attempt for the given IP address.

        Called AFTER a wrong password is detected.  Increments the running
        failure counter for this IP and blocks it once MAX_ATTEMPTS is reached
        within the TIME_WINDOW.

        If the last failure was outside the time window, the counter resets —
        this prevents permanently escalating counts for occasional honest mistakes.

        Args:
            ip_address: The IP of the client that failed to log in.
            username:   (Optional) The username that was attempted — used only
                        for the security alert log message.
        """
        current_time = time.time()

        # ── First failure from this IP in our records ──────────────────────────
        if ip_address not in self.failed_attempts:
            # Start a brand-new failure window: count = 1, window starts now
            self.failed_attempts[ip_address] = (1, current_time)

        # ── IP already has a failure history ──────────────────────────────────
        else:
            count, first_time = self.failed_attempts[ip_address]
            # Unpack: count = number of failures so far,
            #         first_time = Unix timestamp of the first failure in this window

            # Check if the current window has expired (last failure was too long ago)
            if current_time - first_time > self.TIME_WINDOW:
                # Time window expired → reset the counter and start a new window
                # (treats old failures as stale; only recent failures matter)
                self.failed_attempts[ip_address] = (1, current_time)

            else:
                # Still within the active time window → increment the failure count
                new_count = count + 1
                # Store updated count while keeping the original window start time
                self.failed_attempts[ip_address] = (new_count, first_time)

                # Check if the failure count has hit or exceeded the threshold
                if new_count >= self.MAX_ATTEMPTS:
                    # Block this IP: set the expiry time to now + BLOCK_DURATION
                    self.blocked_ips[ip_address] = current_time + self.BLOCK_DURATION

                    # Log a security alert to the server console
                    print(
                        f"SECURITY ALERT: Blocked IP {ip_address} "
                        f"after {new_count} failed attempts."
                    )

                    # If a username was provided, log that too for investigation
                    if username:
                        print(f"Suspicious activity detected for user: {username}")

    # ──────────────────────────────────────────────────────────────────────────
    def reset_attempts(self, ip_address: str):
        """
        Clear the failure counter for an IP address after a successful login.

        Called after a correct password is accepted so that a user who had
        some prior failures (but not enough to be blocked) starts with a
        clean slate on their next attempt.
        """
        # Only delete if the IP actually has a recorded failure history;
        # if the key doesn't exist, do nothing (avoids a KeyError)
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]


# ── Module-level singleton ─────────────────────────────────────────────────────
# A single shared SecurityManager instance used by api.py across all requests.
# Because FastAPI runs in a single process (with async workers), this in-memory
# state is shared safely across all concurrent requests on the same server.
security_manager = SecurityManager()
