"""Lab-only UDP responder (benign request/response service). Answers every datagram with a short reply."""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("172.20.0.10", 5300))
while True:
    data, addr = s.recvfrom(512)
    s.sendto(b"resp:" + data[:32], addr)
