import random

# 🔹 Simulated Exfiltrated Data (If You "Hacked" Fraktal)
fake_data = {
    # 🔹 Stolen Credentials & Accounts
    "accounts": [
        "Fraktal Admin: `admin@fraktal.fi` | Password: `Fraktal2024!`",
        "SOC Lead: `threatintel@fraktal.fi` | Password: `Th3Hunter99`",
        "VPN Credentials: `fraktal_user` | Pass: `SecureVPN123!`",
        "AWS IAM Key: `AKIA***************` | Secret: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`",
        "SSH Key Dump: `id_rsa` from `fraktal-internal-server` (Root Access Confirmed)",
        "Client C2 Access: `fraktal-client@secure-c2.fi` | `s3cr3t_payload!`",
    ],

    # 🔹 Internal Chat Logs (Fake Leaks)
    "chat_logs": [
        "[Slack] Red Team Lead: 'We bypassed AV in the latest pentest. Clients won’t be happy if this leaks...'",
        "[Teams] CEO: 'Our SOC keeps missing phishing attempts. We need a new detection approach.'",
        "[Slack] Threat Intel: 'APT-41 is actively targeting Fraktal clients. Phishing with `login-fraktal.fi`.'",
        "[Internal Email] 'Urgent: CVE-2024-XXXX in Fraktal VPN. Patch deployment scheduled for Monday.'",
        "[Confidential Memo] 'Fraktal detected unauthorized access attempt on test environment. Investigation ongoing.'",
    ],

    # 🔹 Leaked Penetration Test Reports
    "pentest_reports": [
        "Fraktal PenTest Report: RCE found in internal VPN. PoC: `curl -X POST <redacted>`",
        "Internal Audit: 3/5 simulated phishing attacks bypassed 2FA. `admin@fraktal.fi` compromised.",
        "Stored XSS in client dashboard: `alert(document.cookie)` payload successfully injected.",
        "Credential Dump from Red Team Engagement: `fraktal-admin:Sup3rS3cur3!` extracted via AD attack.",
        "Cobalt Strike Beacon: Session opened on `192.168.10.5` via phishing payload. Lateral movement successful.",
    ],

    # 🔹 Exploits & Attack Simulation Logs
    "exploits": [
        "MITRE ATT&CK Simulation: `T1114 - Email Collection` on 5 hosts, `T1071 - C2 Channel` established.",
        "SOC Report: Unusual DNS exfiltration from `fraktal-research.com`. Possible data leakage detected.",
        "AV Evasion Report: Successfully bypassed EDR using Shellcode Injection. Detection rate: 0%",
        "Red Team Log: `fraktal-c2-server` pivoted to `client-secure-vpn`. Internal access escalated.",
        "Zero-Day Alert: New CVE discovered in `fraktal-web-vpn` service. Patching recommended ASAP.",
    ]

    # 🔹 Dark Web & Threat Intelligence
 
}

def get_fake_data():
    """Return a randomly selected fake exfiltrated message from any category."""
    category = random.choice(list(fake_data.keys()))
    return random.choice(fake_data[category])