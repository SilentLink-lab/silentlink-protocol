# examples/server.py

import asyncio
from silentlink.server import Server

def start_server():
    server = Server()
    server.start()

if __name__ == '__main__':
    start_server()
