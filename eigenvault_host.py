#!/usr/bin/env python3
import sys
import json
import struct
import os
from pathlib import Path

# Path to the vault file used by the CLI
VAULT_FILE = Path.home() / ".eigenvault.ev"

def get_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    message_length = struct.unpack('=I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message):
    content = json.dumps(message).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('=I', len(content)))
    sys.stdout.buffer.write(content)
    sys.stdout.buffer.flush()

def main():
    while True:
        try:
            message = get_message()
            if message is None:
                break

            if message['type'] == 'READ_VAULT':
                if VAULT_FILE.exists():
                    with open(VAULT_FILE, 'rb') as f:
                        data = f.read()
                    send_message({'success': True, 'data': list(data)})
                else:
                    send_message({'success': False, 'error': 'Vault file not found'})

            elif message['type'] == 'WRITE_VAULT':
                data = bytes(message['data'])
                with open(VAULT_FILE, 'wb') as f:
                    f.write(data)
                send_message({'success': True})

            elif message['type'] == 'PING':
                send_message({'success': True, 'message': 'pong'})

        except Exception as e:
            send_message({'success': False, 'error': str(e)})

if __name__ == '__main__':
    main()
