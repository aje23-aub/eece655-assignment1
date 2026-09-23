#!/usr/bin/env python3.11

from http_server import run_server

if __name__ == "__main__":
    # Launch the HTTP server (port 80 requires root/sudo privileges on Linux)
    run_server(host="0.0.0.0", port=80)
