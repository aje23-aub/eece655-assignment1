#!/usr/bin/env python3
import json           # Encodes Python payload dictionary into JSON format.
import time           # Provides sleep delay...
import urllib.request # Handles HTTP request generation and dispatch to Telegram API.

# Telegram Bot API credentials.
TOKEN = "8956510966:AAHC3srxJLFmTMB-JejwCtTbffKnzaIbeeY"
CHAT_ID = "6835023010"

# Open target audit log file for tailing.
with open("/tmp/audit.log", "r", encoding="utf-8") as f:

    # Jump directly to the end of the file...
    f.seek(0, 2)

    # Continuous polling loop to tail newly appended log messages.
    while True:

        # Read and strip whitespace from newly appended line.
        line = f.readline().strip()

        # Process and dispatch log entries.
        if line:

            # Format Telegram notification payload as JSON bytes.
            payload = json.dumps({"chat_id": CHAT_ID, "text": line}).encode("utf-8")

            # Build HTTP POST request targeting the Telegram Bot sendMessage endpoint.
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                data=payload,
                headers={"Content-Type": "application/json"}
            )

            # Dispatch HTTP POST request to Telegram API.
            urllib.request.urlopen(req)

        # Pause for 1 second then repeat...
        time.sleep(1)

