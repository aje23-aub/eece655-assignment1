#!/usr/bin/env python3
# Standard library imports for SSH execution and file polling.
import subprocess
import time

# SSH configuration for utilities server (Machine B).
SSH_KEY = "/root/.ssh/id_rsa_utilities"
REMOTE_HOST = "utilities@10.40.40.22"
REMOTE_FILE = "/tmp/audit.log"
LOCAL_FILE = "/tmp/audit.log"

# Open local audit log file for tailing.
with open(LOCAL_FILE, "r", encoding="utf-8") as f:

    # Jump to end of file to ignore past log entries.
    f.seek(0, 2)

    # Continuous polling loop to forward newly appended lines.
    while True:

        line = f.readline()
        if line:

            # Construct SSH command to append line to remote /tmp/audit.log.
            ssh_cmd = [
                "ssh",
                "-i", SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                REMOTE_HOST,
                f"cat >> {REMOTE_FILE}"
            ]

            try:
                # Pipe new line via SSH stdin to utilities server.
                subprocess.run(ssh_cmd, input=line.encode("utf-8"), timeout=5)
            except Exception as e:
                print(f"[!] Log forwarding error: {e}")

        # Pause for 1 second to reduce CPU usage.
        time.sleep(1)
