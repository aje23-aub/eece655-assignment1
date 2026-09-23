# AI Prompts & Outputs Log — Defender (Anwar El Fatayri)

## 1. GenAI Usage Overview & Attribution Statement
* **Author / Defender:** Anwar El Fatayri
* **Course:** EECE655 — Internet Security (Dr. Imad H. Elhajj)
* **Primary AI Assistant Used:** Gemini / ChatGPT
* **Scope of GenAI Usage:** Front-end HTML/CSS template generation (`index.html`, `dashboard.html`, `login_failed.html`) and low-level binary DNS packet parsing (`build_dns_response()` in `dns_server.py`).
* **Hand-Coded Core Logic:**
  - Custom Python raw socket HTTP server (`http_server.py`) and versioned security modes (v0, v1, v2, v3).
  - Database connection, schema handling, and parameterized MariaDB queries (`pymysql`).
  - Log forwarding daemon (`log_forwarder.py`) utilizing SSH channels between Machine A and Machine B.
  - Real-time Telegram notification engine (`send_notifications.py`).
  - DNS anomaly evaluation thresholds (QNAME length/entropy checks and EDNS0 OPT trigger rules).

---

## 2. Prompts, Outputs, and Code Mapping

### Entry D1: Front-End Web Application UI Templates (`index.html`, `dashboard.html`, `login_failed.html`)
* **Date & AI Tool:** September 2026 — Gemini
* **User Prompt:**
  > *"Generate clean HTML/CSS templates for a network monitoring web portal including a login page (`index.html`), an admin service health status dashboard (`dashboard.html`), and an authentication failure page (`login_failed.html`) with modern card layouts."*
* **GenAI Usage Rationale:**
  - UI design and front-end layout HTML/CSS code go beyond the security and backend networking scope of this assignment.
  - The HTML templates were obtained from GenAI and subsequently integrated into the raw Python socket response engine, with minor manual tweaks made to align dynamic rendering placeholders (e.g., `{row}`, `{status}`, table rows).
* **Code Mapping & Integration:**
  - Integrated directly into `http_server.py` on Machine A (`10.40.40.21`) within HTTP response header/body formatting handlers.

---

### Entry D2: Binary DNS Response Construction & Field Extraction (`dns_server.py`)
* **Date & AI Tool:** September 2026 — Gemini
* **User Prompt:**
  > *"Write a Python function with comments using raw byte manipulation and socket operations to parse an incoming DNS UDP query header, extract the QNAME subdomain labels, search for EDNS0 TYPE 41 OPT Pseudo-RR bytes to extract custom option fields, and construct a valid DNS TXT response packet without using third-party DNS libraries."*
* **Raw AI Output Code:**
```python
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