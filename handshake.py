import hashlib
import base64

MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def parse_http_headers(http_data: bytes) -> dict:
    headers = {}
    lines = http_data.decode().split("\r\n")
    for line in lines[1:]:  # skip the GET line
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key.lower()] = value
    return headers

def generate_accept_key(sec_websocket_key: str) -> str:
    combined = sec_websocket_key + MAGIC_STRING
    sha1_hash = hashlib.sha1(combined.encode()).digest()
    return base64.b64encode(sha1_hash).decode()

def perform_handshake(client_socket) -> bool:
    request = client_socket.recv(1024)
    headers = parse_http_headers(request)

    if "sec-websocket-key" not in headers:
        print("Invalid handshake: missing Sec-WebSocket-Key")
        return False

    accept_key = generate_accept_key(headers["sec-websocket-key"])
    
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )

    client_socket.send(response.encode())
    return True
