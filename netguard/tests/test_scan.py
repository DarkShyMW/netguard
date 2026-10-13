import socket
import threading
import time
import pytest
from netguard.scan import scan_port

class TCPSimulator(threading.Thread):
    def __init__(self, port, response=None, refuse=False):
        super().__init__()
        self.port = port
        self.response = response
        self.refuse = refuse
        self.sock = None
        self.daemon = True

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(('127.0.0.1', self.port))
            self.sock.listen(1)
            conn, addr = self.sock.accept()
            if self.refuse:
                conn.close()
            elif self.response:
                conn.sendall(self.response.encode())
                time.sleep(0.1)
                conn.close()
            else:
                conn.recv(1024)
                conn.close()
        except Exception:
            pass
        finally:
            if self.sock:
                self.sock.close()

def test_scan_open_port_with_banner():
    sim = TCPSimulator(12345, response="220 FTP Server Ready")
    sim.start()
    time.sleep(0.1) # Wait for bind
    
    result = scan_port("127.0.0.1", 12345, timeout=1.0)
    assert result.is_open
    assert "FTP" in result.banner
    
    sim.join(timeout=1.0)

def test_scan_refused_port():
    sim = TCPSimulator(12346, refuse=True)
    sim.start()
    time.sleep(0.1)
    
    result = scan_port("127.0.0.1", 12346, timeout=1.0)
    assert not result.is_open
    
    sim.join(timeout=1.0)

def test_scan_timeout_unroutable():
    # RFC 5737 TEST-NET address
    start_time = time.time()
    result = scan_port("192.0.2.1", 80, timeout=0.5)
    duration = time.time() - start_time
    
    assert not result.is_open
    assert duration < 1.0 # Should respect timeout roughly