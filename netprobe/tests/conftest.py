import socket
import threading
import time

import pytest


@pytest.fixture
def banner_server():
    """Start throwaway TCP servers on 127.0.0.1 that greet with a fixed banner."""
    started = []

    def start(banner: bytes = b"") -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        srv.settimeout(0.2)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    try:
                        if banner:
                            conn.sendall(banner)
                        conn.settimeout(0.2)
                        conn.recv(1024)
                    except OSError:
                        pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started.append((srv, stop, thread))
        return srv.getsockname()[1]

    yield start

    for srv, stop, thread in started:
        stop.set()
        srv.close()
        thread.join(timeout=1)


@pytest.fixture
def closed_port():
    """A local port that nothing is listening on."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    time.sleep(0.05)
    return port
