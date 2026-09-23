#!/usr/bin/env python3
from dns_server import run_dns_server

if __name__ == "__main__":
      # Run the DNS server listener
        run_dns_server(host="0.0.0.0", port=53)
