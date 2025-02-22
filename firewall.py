# client_firewall_simulation.py

import base64
import time
import logging

# Set up logging to output to a file (append mode) and to the console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("firewall_log.txt", mode="a")
    ]
)

class MiniFirewallIDS:

    def __init__(self, suspicious_word_list=None, max_frag_per_window=6, window_seconds=5, blocked_ports=None):
        """
        :param suspicious_word_list: Keywords to block if found in decoded fragment.
        :param max_frag_per_window: Maximum fragments allowed within a time window.
        :param window_seconds: The time window (in seconds) for rate-based limiting.
        :param blocked_ports: A list of outbound ports to simulate as blocked.
        """
        self.suspicious_word_list = suspicious_word_list or ["password", "secret", "internal"]
        self.max_frag_per_window = max_frag_per_window
        self.window_seconds = window_seconds
        self.fragment_timestamps = []  # For rate limiting
        self.blocked_ports = blocked_ports or [23, 25, 135, 137, 138, 139, 445, 8443, 1194]

    def inspect_fragment(self, fragment):
        """
        Inspects a single fragment (without combining them) for:
          - Rate limits (if too many fragments sent in a short window)
          - Suspicious keywords in the Base64-decoded content
      
        :return: (allowed: bool, reason: str)
        """
        now = time.time()

        # Rate-based check: Remove timestamps older than our window
        self.fragment_timestamps = [t for t in self.fragment_timestamps if now - t <= self.window_seconds]
        if len(self.fragment_timestamps) >= self.max_frag_per_window:
            reason = f"BLOCKED Rate limit exceeded: {len(self.fragment_timestamps)} fragments in the last {self.window_seconds}s"
            logging.info(reason)
            return (False, reason)

        self.fragment_timestamps.append(now)

        # Decode only this fragment
        decoded_str = ""
        try:
            decoded_bytes = base64.urlsafe_b64decode(fragment)
            decoded_str = decoded_bytes.decode(errors="ignore")
        except Exception:
            pass

        # Check for suspicious keywords
        for word in self.suspicious_word_list:
            if word.lower() in decoded_str.lower():
                reason = f"BLOCKED Suspicious keyword '{word}' found in fragment"
                logging.info(reason)
                return (False, reason)

        return (True, "Allowed")

    def inspect_port(self, port):
        """
        Simulates an outbound port check.
        
        :param port: Destination port number
        :return: (allowed: bool, reason: str)
        """
        if port in self.blocked_ports:
            reason = f" BLOCKED : Outbound port {port} is blocked"
            logging.info(reason)
            return (False, reason)
        reason = "Port allowed"
        logging.info(f"Request to access port {port} is approved")
        return (True, reason)

    def reset(self):
        """Reset the firewall's rate limiter counters."""
        self.fragment_timestamps.clear()
        logging.info("Firewall traffic rate limiter is reset")
