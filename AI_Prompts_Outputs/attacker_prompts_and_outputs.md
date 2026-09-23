# AI Prompts & Outputs Log — Attacker (Jad Eido)

## 1. GenAI Usage Overview & Attribution Statement
* **Author / Attacker:** Jad Eido
* **Course:** EECE655 — Internet Security (Dr. Imad H. Elhajj)
* **Primary AI Assistant Used:** Gemini
* **Scope of GenAI Usage:** HTTP request structure and urllib boilerplate (`inject()` function in `attack_v1.py` and `post()` function in `attack_v2.py`), and binary DNS response construction and EDNS0 OPT field extraction (`build_dns_response()` in `dnssniffer.py`).
* **Hand-Coded Core Logic:**
  - SQL injection payloads targeting the `username` field to dump admin credentials via `UNION SELECT ... INTO OUTFILE` (`attack_v1.py`, `injection1_sqli()`).
  - OS command injection payloads to deploy the DNS sniffer on Machine B via SSH pivot using base64-encoded scripts (`attack_v1.py`, `injection2_deploy()`).
  - DNS QNAME exfiltration payload using `awk` and `dig` to hide the hash in the subdomain label (`attack_v1.py`, `injection3_exfil()`).
  - SSRF OS command injection payloads targeting the `check_services` port field to bypass Iteration 1 detection (`attack_v2.py`).
  - EDNS0 OPT exfiltration payload using `dig +ednsopt=65001` to hide the hash in the DNS additional section (`attack_v2.py`, `injection3_exfil()`).
  - QNAME parser (`parse_qname()`) and Telegram alert delivery (`send_telegram_alert()`) in `dnssniffer.py`.
  - Base64 encoding and deployment pipeline for remote sniffer installation on Machine B.

---

## 2. Prompts, Outputs, and Code Mapping

### Entry A1: HTTP Request Helper — urllib Boilerplate (`attack_v1.py`, `attack_v2.py`)
* **Date & AI Tool:** September 2026 — Gemini
* **User Prompt:**
  > *"Write a Python function using only stdlib urllib to send a POST request with form-encoded fields to a web server, percent-encoding the field values so that special characters like single quotes, semicolons and hash signs are preserved in transport. Return the HTTP status code and response body as a tuple. Handle HTTPError so that 4xx and 5xx responses are still readable."*
* **GenAI Usage Rationale:**
  - The `urllib` request structure, percent-encoding handling, and `HTTPError` catch pattern required boilerplate knowledge that went beyond the security focus of the assignment. Gemini was used to generate the structural skeleton; all injection payloads, field names, and logic were authored by the student.
* **Raw AI Output Code:**
```python
def inject(username: str) -> tuple:
    encoded_username = urllib.parse.quote(username, safe="")
    raw_body = f"action=login&username={encoded_username}&password="
    data = raw_body.encode("utf-8")

    req = urllib.request.Request(
        TARGET_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
```
* **Code Mapping & Integration:**
  - Adapted into `inject()` in `attack_v1.py` and `post()` in `attack_v2.py`. Additional browser-spoofing headers (`User-Agent`, `Referer`, `Accept`, `Accept-Language`) were manually added by the student to bypass Cloudflare bot protection encountered during testing. The `post()` function in `attack_v2.py` was further extended to accept a dictionary of fields and encode them all, to support the `check_services` endpoint's additional `server`, `service`, and `port` parameters.

---

### Entry A2: Binary DNS Response Construction & EDNS0 OPT Field Extraction (`dnssniffer.py`)
* **Date & AI Tool:** September 2026 — Gemini
* **User Prompt:**
  > *"Write a Python function using raw byte manipulation to parse an incoming DNS UDP query, extract the QNAME from the question section, search the additional section for an EDNS0 OPT pseudo-RR (TYPE 41 / 0x0029), extract its RDATA payload, and construct a valid DNS TXT response packet — all without using any third-party DNS libraries."*
* **GenAI Usage Rationale:**
  - The DNS wire format (header layout, QNAME label encoding, OPT record structure, TXT RDATA construction) requires low-level binary protocol knowledge not covered in the course. Gemini was used to generate the byte-manipulation skeleton. The student integrated the output into the sniffer, corrected the EDNS0 payload decoding (changing `.decode("utf-8")` to `.hex()` to correctly recover the hash from raw binary bytes), and wired the extracted fields into the QNAME and EDNS0 detection branches.
* **Raw AI Output Code:**
```python
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
```
* **Student Modifications to AI Output:**
  - Changed `edns0_opt = edns0_raw.decode("utf-8", errors="ignore")` to `edns0_opt = edns0_raw.hex()` — confirmed via `tcpdump` analysis that `dig +ednsopt` sends the hash as raw binary bytes, not a UTF-8 string, so `.hex()` is required to reconstruct the original MD5 hash string.
  - Integrated `build_dns_response()` into the main sniffer loop, replacing separate `parse_qname()` and `parse_edns0_opt()` calls with a single unified parse pass.
  - Added QNAME and EDNS0 detection branches and Telegram alert dispatch on extracted fields.
* **Code Mapping & Integration:**
  - Integrated into `dnssniffer.py` on Machine B (`10.40.40.22`). The function is called in the main `while True` loop and its three return values (`resp_bytes`, `qname`, `edns0_opt`) drive both the Iteration 1 QNAME detection and the Iteration 2 EDNS0 OPT detection.
