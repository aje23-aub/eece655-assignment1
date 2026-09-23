#!/usr/bin/env python3

# Import required libraries.
import hashlib      # Password hashing.
import os           # File and path operations.
import socket       # Network socket handling.
import subprocess   # OS command execution.
import pymysql      # MariaDB/MySQL connectivity.

from urllib.parse import parse_qs             # HTTP form parameter parsing.
from ipaddress import ip_address, ip_network  # IP and network validation.


# Global configuration variables...
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

CURRENT_VERSION = "v0" # Global server version (defaults to v0)
DB_NAME = "portal"
DB_ADMIN_USER = "portal_admin"
DB_ADMIN_PASS = "portal@dminpa$$word123"

DASHBOARD_CONTEXT = {
    "username": "",
    "role": "",
    "db_name": "",
    "server_IP": "",
    "ssh_key_path": "",
    "ssh_status_message": """
        <div class="alert-info">
            <strong>Direct SSH initiation is restricted to the local corporate network...</strong>
        </div>
    """,
}


# Securely write the active version to a file on the utilities server via SSH.
def sync_version_to_utilities(current_server_version):

    # Configuration for remote SSH access.
    ssh_key_path = "/root/.ssh/id_rsa_utilities"
    remote_host = "utilities@10.40.40.22"
    remote_file = "/tmp/server_version.txt"

    # Construct SSH command list to prevent shell injection
    ssh_cmd = [
        "ssh",
        "-i",
        ssh_key_path,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
        remote_host,
        f"cat > {remote_file}"
    ]
    
    try:
        # Execute SSH subprocess and pipe current server version via stdin.
        subprocess.run(ssh_cmd, input=f"{current_server_version}".encode("utf-8"), check=True, timeout=5)

        # Log successful version synchronization.
        print(f"[+] Successfully wrote version '{current_server_version}' to utilities:{remote_file}")

    # Log unexpected SSH synchronization errors.
    except Exception as e:
        print(f"[!] Failed to update version on utilities server: {e}")


# Load an HTML template from disk and replace placeholders using the values provided in the context dictionary.
def render_template(filename, context=None):

    # Build the full path to the template file.
    path = os.path.join(TEMPLATE_DIR, filename)

    # Return an error page if the template does not exist.
    if not os.path.exists(path):
        return f"<h1>500 Template Error: {filename} missing</h1>"

    # Read the template content into memory.
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Replace template variables with their corresponding values.
    if context:
        for key, val in context.items():

            # Replace occurrences of {{variable_name}}
            # with the provided value.
            content = content.replace(
                f"{{{{{key}}}}}", str(val if val is not None else "")
            )

    # Return the rendered template.
    return content


# This function handles user requests.
# It processes both login attempts, SSH connection requests and network services status requests.
# Multiple vulnerabilities are intentionally included for exploitation during the assignment.
def handle_requests(body_str, client_ip):

    # Get current server's version
    global CURRENT_VERSION

    # Parse HTTP POST parameters from the request body.
    params = parse_qs(body_str)

    # Extract the requested action.
    request_type = next(iter(params.get("action", [""])), "")
          
    # Extract the supplied/current username.
    username = next(iter(params.get("username", [""])), "") 
    
    print(f"PARAMS ========= {params}\n")
    print(f"REQUEST ========= {request_type}\n")

    # Switch server version request...
    if request_type == 'set_version':
    
        # Extract the requested server version.
        CURRENT_VERSION = next(iter(params.get("version", ["v0"])), "v0")
        
        # Log server mode change.
        print(f"[+] Server Security Mode set to: {CURRENT_VERSION}")
        
        #  Securely sync the version to utilities server.
        sync_version_to_utilities(CURRENT_VERSION)
        
        # return the index...
        return 200, render_template("index.html") 
        
    # Login / Authentication request...
    elif request_type == 'login':

        # Extract the supplied password.
        password = next(iter(params.get("password", [""])), "")

        # Generate the MD5 hash of the supplied password.
        # Intentionally using a weak hashing algorithm...
        pwd_hash = hashlib.md5(password.encode()).hexdigest()


        # !!!!! SQL INJECTION VULNERABILITY !!!!!
        #
        # Later, the server blindly executes this SQL command in the database to authenticate the user.
        # No input validation or syntax checks are performed before execution.
        # This creates an opportunity for an attacker to execute arbitrary SQL commands with elevated privileges !
        sql_auth_query = (
            f"SELECT * FROM users WHERE username='{username}' AND"
            f" password_hash='{pwd_hash}'"
        )
        

        # !!!!! OS COMMAND INJECTION VULNERABILITY !!!!!
        #
        # For any authentication request, we are blindly running this command (via system shell).
        # The objective is to simply write an informative audit log about user authentication attempt.
        # This opens the opportunity to an attacker to execute arbitrary command with root privileges !
        cmd_log = f"echo [AUDIT LOG] Request for user: {username} >> /tmp/audit.log"
        
        #print(f" COMMMMAAAANNND ==================== {cmd_log}\n")
        
    
        # ----- Defense Code -----
        
        # Login SQL and os command injection detection...        
        # Detected & Alerted, but UNBLOCKED: Log alert to audit log and continue execution
        if CURRENT_VERSION in ["v1", "v2"]: 
            if "'" in username or ";" in username or "#" in username:
                # Log a detected login attack to the audit log.
                cmd_alert_log = (   
                  f"echo '[⚠️ ALERT] {CURRENT_VERSION} Login Attack Detected from {client_ip}!' >>"
                  " /tmp/audit.log"
                )
                subprocess.Popen(cmd_alert_log, shell=True)
                
        # Detected & BLOCKED: Log blocked attempt and return 401 Login Failed immediately.
        elif CURRENT_VERSION == "v3":
            # Hardened v3: Native Python file append (Zero shell exposure)
            with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                f.write(f"[🛡️ BLOCKED] v3 Login Attack Blocked from {client_ip}!\n")
                
            # Exit and return 401 along with the rendered login_failed.html template
            return 401, render_template("login_failed.html", DASHBOARD_CONTEXT)
    
    
    
        subprocess.Popen(cmd_log, shell=True)
        
        
        # Connect to DB and authenticate the user via the vulnerable SQL query...
        try:
            conn = pymysql.connect(
                host="localhost",
                user=DB_ADMIN_USER,
                password=DB_ADMIN_PASS,
                database=DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
            )

            cursor = conn.cursor()
            cursor.execute(sql_auth_query)
            row = cursor.fetchone()

            # Close DB connection...
            conn.close()


            # If the user was found...
            if row:

                # Store the password hash.
                db_pwd_hash = row.get("password_hash")

                # !!!!! SQL INJECTION VULNERABILITY !!!!!
                #
                # Made on purpose to let the attacker bypass this check with the 'utilites' user (password hash in NULL is DB)
                # Password hash verification for accounts with set passwords -> all users in DB except utilities
                if db_pwd_hash is not None and db_pwd_hash != pwd_hash:
                    return 401, render_template("login_failed.html", DASHBOARD_CONTEXT)

                # Successful SQL Injection bypass for utilities (password_hash = NULL)
                else:
                    return 200, render_template("dashboard.html", DASHBOARD_CONTEXT)

            # If no matching user was found...
            else:
                return 401, render_template("login_failed.html", DASHBOARD_CONTEXT)

        # SQL / DB Errors...
        except Exception as e:
            
            # Detected & BLOCKED: Log blocked attempt and return Database error without revealing details.
            if CURRENT_VERSION == "v3":
            
                # Hardened v3: Native Python file append (Zero shell exposure)
                with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                    f.write(f"[🛡️ BLOCKED] v3 Login SQL Injection in DB - Attack Blocked from {client_ip}!\n")
                
                # Return an Database error page withot the exception details...
                return 500, f"<h2>Database Error</h2><p></p>"
            
            # Version 0,1 or 2...
            else: 
                # Intentionally left to reveal sensitive information for the attacker.
                return 500, f"<h2>Database Error</h2><p>{e}</p>"
            
            
    # SSH request
    # Once authenticated as utilities the button "CONNECT VIA SSH" is there to let the admin ssh to the utilities server
    elif request_type == 'ssh_connect':
    
        # !!!!! INFORMATION DISCLOSURE VULNERABILITY !!!!!
        #
        # Failed SSH requests expose internal infrastructure details (assuming debug information should be returned in such cases).
        # Sensitive information such as server IPs, usernames, roles, database names, and SSH key paths is disclosed to the user.
        # This enables an attacker to perform reconnaissance and identify valuable internal targets !
        
        # SSH network access failure message.
        ssh_error_status_msg = f"""
        <div class="alert-danger">
            <strong>SSH Connection Failed:</strong> Access denied for client IP ({client_ip}).
            Direct SSH initiation is restricted to the local corporate network (10.40.40.0/24).
        </div>
        """

        # SSH network access success message.
        ssh_success_status_msg = f"""
        <div class="alert-danger">
            <strong>SSH connection established successfully. Welcome to the Utilities Server.</strong>
        </div>
        """

        # SSH Debug info (disclosure vulnerability)...
        ssh_error_context = {
            "username": username if username else "utilities",
            "role": "admin",
            "db_name": DB_NAME,
            "server_IP": "10.40.40.22",
            "ssh_key_path": "/root/.ssh/id_rsa_utilities",
            "ssh_status_message": ssh_error_status_msg,
        }

        # SSH Success context...
        # We will never reach this context, so we will keep the debug info anyway and change the message.
        ssh_success_context = {
            "username": username if username else "utilities",
            "role": "admin",
            "db_name": DB_NAME,
            "server_IP": "10.40.40.22",
            "ssh_key_path": "/root/.ssh/id_rsa_utilities",
            "ssh_status_message": ssh_success_status_msg,
        }
    
        # If anyone attemps to connect from outside the network...
        # The function returns network access failure error message.
        # We assume that the Utilities Dashboard is inaccessible from external networks.
        # This vulnerability will be exploited later to bypass password authentication !

        # Allowed (local) networks to connect from...
        allowed_networks = [
            ip_network("10.40.40.0/24"),
            ip_network("127.0.0.1/32"),
        ]

        # If the connection originates from an authorized local IP address...
        if any(ip_address(client_ip[0]) in net for net in allowed_networks):

            # In the context of this assignment, we will not develop this part (opening a real ssh session to utilities server).
            return 200, render_template("dashboard.html", ssh_success_context)

        # If the connection originates from an unauthorized IP address...
        else:
            # Detected & BLOCKED: Log blocked attempt and return the dashboard page without revealing DB info.
            # Please note that the attacker will not reach this page in v3
            # Therefore, we will not develope session CURRENT_VERSION variable to maintain it among pages...
            # It's just a demo on how we could've stopped revealing sensitive info in v3 !
            if CURRENT_VERSION == "v3":
            
                # SSH Debug info -> Set everything to "" to ensure that no info disclosure will occur...
                ssh_error_context = {
                    "username": username if username else "utilities",
                    "role": "",
                    "db_name": "",
                    "server_IP": "",
                    "ssh_key_path": "",
                    "ssh_status_message": "",
                }
            
            # For versions 0,1 and 2
            # Return a debug info disclosing sensitive internal details about the utilities server.
            # This is intentionally meant to help the attacker to access the utilities server in a later stage of the attack.
            return 200, render_template("dashboard.html", ssh_error_context)

    # End of SSH connection handling

    # Check network services status request
    elif request_type == 'check_services':
    
        # Port to service mapping...
        port_map = {
            "80": "http",
            "3306": "db",
            "22": "ssh",
            "53": "dns",
            "25": "smtp",
        }
    
        # Extract the server and the service (port) to be checked...
        server_name = params['server'][0]
        server_port = params['port'][0]
        
        # Get the service name (defaults to "service" if port isn't in map)
        server_service = port_map.get(str(server_port), "service")
        
        # Assign the IP to the requested server.
        if server_name == 'utilities':
            server_ip = '10.40.40.22'
        elif server_name == 'local':
            server_ip = '127.0.0.1'
        else: # Keep as it as a help in the next injection vulnerability
            server_ip = server_name


        # !!!!! OS COMMAND INJECTION VULNERABILITY !!!!!
        #
        # Unsanitized server IP/port concatenated directly into a system shell command.
        if server_port == '3306': # For SQL Injection in order to be able to get the admin password hash...
            cmd = f"mysql -u {DB_ADMIN_USER} -p'{DB_ADMIN_PASS}' -h {server_ip} {DB_NAME} -e 'SELECT 1;' 2>&1"
        else:
            cmd = f"nc -zv -w 2 {server_ip} {server_port} 2>&1"
               
        
        # ----- Defense Code -----
        
        # SSRF OS command injection detection...        
        # Detected & Alerted, but UNBLOCKED: Log alert to audit log and continue execution
        if CURRENT_VERSION == "v2": 
            if any(char in server_ip + server_port for char in ["'", ";", "#"]):
                # Log a detected login attack to the audit log.
                cmd_alert_log = (   
                  f"echo '[⚠️ ALERT] {CURRENT_VERSION} SSRF OS COMMAND Injection Attack Detected from {client_ip} !' >>"
                  " /tmp/audit.log"
                )
                subprocess.Popen(cmd_alert_log, shell=True)
                
        # Detected & BLOCKED: Log blocked attempt and return 500 error immediately.
        elif CURRENT_VERSION == "v3":
            # Hardened v3: Native Python file append (Zero shell exposure)
            with open("/tmp/audit.log", "a", encoding="utf-8") as f:
                f.write(f"[🛡️ BLOCKED] v3 SSRF OS COMMAND Injection Attack Blocked from {client_ip}!\n")
                
            # Exit and return 500 error -> Attack detected and blocked...
            return 500, f"<h2>Attack Detected and Blocked</h2><p></p>"

        
        # Launch the command blindly... 
        cmd_output = subprocess.getoutput(cmd)        

        # Build services context based on service status checked previously.
        # We will not do further checks for this assignment.
        services_context = {f"{server_service}_status": "🟢 Online" if cmd else "🔴 Offline"}

        # render the new context with service(s) status...
        return 200, render_template("index.html", services_context)
        
    # No other types of requests so we return the index    
    else:          
        return 200, render_template("index.html")





# Start the HTTP server and process incoming client requests.
def run_server(host="0.0.0.0", port=80):

    # Get current server's version
    global CURRENT_VERSION

    # Create a TCP socket for the web server.
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow immediate reuse of the server port after restart.
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the configured host and port.
    server_sock.bind((host, port))

    # Start listening for incoming client connections.
    server_sock.listen(10)

    # Server startup banner.
    print("==========================================")
    print("  HTTP Server Active (Vulnerable Mode)")
    print(f"  Listening on : {host}:{port}")
    print("==========================================")

    # Continuously accept and process client connections.
    while True:

        # Wait for an incoming TCP connection.
        client_sock, client_addr = server_sock.accept()

        # Extract ONLY the IP address string from the (ip, port) tuple.
        client_ip = client_addr if client_addr else "127.0.0.1"

        try:
        
            # Initiate the data received
            data = b""

            # Read headers
            while b"\r\n\r\n" not in data:
                data += client_sock.recv(4096)

            headers, body = data.split(b"\r\n\r\n", 1)

            # Find Content-Length
            content_length = 0
            for line in headers.decode("utf-8", errors="ignore").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
                    break

            # Read remaining body
            while len(body) < content_length:
                body += client_sock.recv(4096)

            raw_req = (
                headers +
                b"\r\n\r\n" +
                body
            ).decode("utf-8", errors="ignore")
            # Receive and decode the HTTP request.


            # Ignore empty or whitespace-only requests (e.g. browser TCP keepalives).
            if not raw_req or not raw_req.strip():
                continue

            # Separate HTTP headers from the request body safely.
            if "\r\n\r\n" in raw_req:
                headers_part, body_str = raw_req.split("\r\n\r\n", 1)
            elif "\n\n" in raw_req:
                headers_part, body_str = raw_req.split("\n\n", 1)
            else:
                headers_part, body_str = raw_req, ""

            # Get the HTTP method
            method = headers_part.split('\n')[0].split()[0].upper()

            # Handle client requests.
            if method == "POST":
                # Process the POST request.
                status, resp_html = handle_requests(body_str, client_ip)
                body_bytes = resp_html.encode("utf-8")

            # Serve the main portal page for GET requests.
            else:
                #  Set the server's version to v0 and sync it to utilities server.
                CURRENT_VERSION = "v0"
                sync_version_to_utilities(CURRENT_VERSION)
                
                # Return the index page
                status = 200
                resp_html = render_template("index.html")
                body_bytes = resp_html.encode("utf-8")

            # Build the HTTP response headers.
            headers = (
                f"HTTP/1.1 {status} OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")

            # Send the HTTP response to the client.
            client_sock.sendall(headers + body_bytes)

        # Log unexpected server errors.
        except Exception as e:
            print(f"[!] Error: {e}")

        # Close the client connection.
        finally:
            client_sock.close()
            
         



