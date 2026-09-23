#!/usr/bin/env python3
# Import required standard libraries.
import os
import socket

# Static TXT record response message for DNS queries.
RESPONSE_TEXT = b"This is a testing EECE655 assignment server and not a real one"


# Read the active security mode version synced from Http server.
def get_current_version():

    version_file = "/tmp/server_version.txt"

    # Read version file if present on disk.
    if os.path.exists(version_file):
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                version = f.read().strip()
                if version:
                    return version
        except Exception:
            pass

    # Default to unmonitored v0 mode if sync file is not found.
    return "v0"



""" ------------- AI Tools Development -------------  
  Parses incoming DNS query header & question, and crafts a valid TXT response.
  It also extracts QNAME and EDNS0-OPT fields from raw query.
"""

# Build a DNS TXT response packet and extract QNAME and EDNS0-OPT fields from raw query.
def build_dns_response(data):

    # Extract transaction ID from query header.
    transaction_id = data[:2]

    # Standard query response flags (No Error: 0x8180).
    flags = b"\x81\x80"

    # Copy Question Count from request and set Answer Count to 1.
    qdcount = data[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    # Assemble 12-byte DNS response header.
    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # =========================================================
    # 1. EXTRACT QNAME FROM QUESTION SECTION (Starts at Byte 12)
    # =========================================================
    labels = []
    idx = 12

    # Loop through domain labels until the root zero byte (0x00) is reached.
    while idx < len(data) and data[idx] != 0:
        label_length = data[idx]
        label = data[idx + 1 : idx + 1 + label_length].decode("utf-8", errors="ignore")
        labels.append(label)
        idx += 1 + label_length

    # Join labels into full QNAME string (e.g. 'dXRpbGl0aWVzCg==.eece655.fun').
    qname = ".".join(labels)

    # Calculate end index of Question section (QNAME + 0x00 + 2-byte QTYPE + 2-byte QCLASS).
    question_end = idx + 1 + 4
    question_section = data[12:question_end]

    # =========================================================
    # 2. EXTRACT EDNS0-OPT PAYLOAD FROM ADDITIONAL SECTION
    # =========================================================
    edns0_opt = ""

    # Search for OPT Pseudo-RR marker (TYPE 41 / 0x0029) past the Question section.
    opt_idx = data.find(b"\x00\x29", question_end)
    if opt_idx != -1 and opt_idx + 10 <= len(data):

        # Read RDLENGTH (2 bytes following TYPE, CLASS, and TTL).
        rdlength = int.from_bytes(data[opt_idx + 8 : opt_idx + 10], byteorder="big")
        rdata_start = opt_idx + 10

        # Extract raw EDNS0 payload string if present.
        if rdata_start + rdlength <= len(data):
            edns0_raw = data[rdata_start : rdata_start + rdlength]
            edns0_opt = edns0_raw.decode("utf-8", errors="ignore")

    # =========================================================
    # 3. CONSTRUCT TXT ANSWER RECORD SECTION
    # =========================================================
    ans_name = b"\xc0\x0c"  # Name pointer to Question section.
    ans_type = b"\x00\x10"  # TXT record type (16).
    ans_class = b"\x00\x01"  # IN class (1).
    ans_ttl = b"\x00\x00\x00\x3c"  # TTL: 60 seconds.

    # Calculate TXT data length prefix and assemble RDATA.
    txt_len = len(RESPONSE_TEXT)
    rdlength = (txt_len + 1).to_bytes(2, byteorder="big")
    rdata = bytes([txt_len]) + RESPONSE_TEXT

    answer_section = ans_name + ans_type + ans_class + ans_ttl + rdlength + rdata
    resp_bytes = header + question_section + answer_section

    # Return packet bytes along with extracted QNAME and EDNS0-OPT parameters.
    return resp_bytes, qname, edns0_opt
	
""" ------------- END of AI Tools Development -------------  """




# ----- Defense Code -----

# Inspect extracted QNAME and EDNS0-OPT parameters for DNS exfiltration attacks.
def inspect_dns_security(qname, edns0_opt, client_ip, current_version):

    # Extract leftmost subdomain label from QNAME.
    subdomain = qname.split(".")[0] if "." in qname else qname
    
    
    print(f"EDNS0_OPT ========== {edns0_opt} \n QNAME ===== {qname}  --------------- \n subdomain ===== {subdomain}\n   LENGTH === {len(subdomain)} \n")

    # Check for QNAME exfiltration payload (high-entropy / long string).
    is_qname_attack = len(subdomain) > 20 or any(char in subdomain for char in ["=", "+", "/"])

    # Check for EDNS0-OPT cover exfiltration payload.
    is_edns0_attack = len(edns0_opt) > 0 and any(char in edns0_opt for char in ["=", "+", "/"])

    # If no attack indicators are found, allow query normally.
    if not is_qname_attack and not is_edns0_attack:
    
        print("NO ATTACK DETECTED\n")
        return True

    #print(f"YOYO Version == {current_version} \n")


    # Version v0: Attacks undetected and unblocked.
    if current_version == "v0":
        return True


    # Version v1: 
    # QNAME exfiltration detected but unblocked.
    # EDNS0-OPT full bypass active.
    elif current_version == "v1":
        if is_qname_attack:
            log_entry = f"[⚠️ ALERT] {current_version} QNAME Exfiltration Detected from {client_ip}: {qname}\n"
            with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
                
        # Only Qname exfiltration detection + alerting...        
        return True  
    
    
    # Version v2: 
    # QNAME exfiltration detected but unblocked.
    # EDNS0-OPT exfiltration detected but unblocked.
    elif current_version == "v2":
        print(f"HIIIIIIIIIIIIIIIIIIIIIIIII =============== {edns0_opt}\n")
        if is_qname_attack: # QNAME exfiltration detected...
            log_entry = f"[⚠️ ALERT] {current_version} QNAME Exfiltration Detected from {client_ip}: {qname}\n"
            with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
        if is_edns0_attack: # EDNS0-OPT exfiltration detected...
            log_entry = f"[⚠️ ALERT] {current_version} EDNS0-OPT Exfiltration Detected from {client_ip}: {qname}\n"
            with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
                
        # Only QNAME or EDNS0-OPT exfiltration detection + alerting...        
        return True

    # Version v3: Fully hardened !
    # Both QNAME and EDNS0-OPT vectors detected and blocked.
    elif current_version == "v3":
        if is_qname_attack or is_edns0_attack:
            log_entry = f"[🛡️ BLOCKED] v3 DNS Exfiltration Blocked from {client_ip} (QNAME: {qname} | EDNS0: {edns0_opt})\n"
            with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
            return False  # Block both vectors in v3.

    return True


# Start the DNS server and process incoming client requests.
def run_dns_server(host="0.0.0.0", port=53):

    # Create a UDP socket for the DNS server.
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Allow immediate reuse of the server port after restart.
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the configured host and port.
    try:
        server_sock.bind((host, port))
        print("==========================================")
        print("  DNS Server Active (EECE655 Testing Mode)")
        print(f"  Listening on : UDP {host}:{port}")
        print("==========================================")
    except PermissionError:
        print(f"[!] Permission denied: Binding port {port} requires root privileges (sudo).")
        return

    # Continuously receive and process client DNS requests.
    while True:

        try:
            # Receive incoming UDP packet data and client address.
            data, client_addr = server_sock.recvfrom(512)

            # Extract ONLY the IP address string from the (ip, port) tuple.
            client_ip = client_addr if client_addr else "127.0.0.1"

            # Ignore truncated or invalid DNS query packets.
            if not data or len(data) < 12:
                continue

            # Fetch the current mode version from sync file.
            current_version = get_current_version()
            
            # Build DNS response packet and extract QNAME & EDNS0 fields.
            resp_bytes, qname, edns0_opt = build_dns_response(data)

            # Perform security inspection on extracted fields.
            if not inspect_dns_security(qname, edns0_opt, client_ip, current_version):
                continue

            # Send the DNS response back to the client.
            server_sock.sendto(resp_bytes, client_addr)

        # Log unexpected server errors.
        except Exception as e:
            print(f"[!] Error: {e}")
