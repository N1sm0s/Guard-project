"""Lab-only UDP request client (benign DNS-like lookups): new source port per request, waits for reply."""
import socket, time
end = time.time() + 600
n = 0
while time.time() < end:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.sendto(b"lookup-%d" % n, ("172.20.0.10", 5300))
        s.recvfrom(512)
        n += 1
    except OSError:
        pass
    s.close()
    time.sleep(1.5)
print("replies", n, flush=True)
