"""One bounded, cancellable HTTPS request to the fixed DeepSeek endpoint.

Only the trusted service supplies request bytes and a live permission guard.
This module never consults proxy environment variables, follows redirects,
retries, or includes provider error text in an exception. A cancelled DNS call
may outlive the caller in a daemon thread, but cannot later send credentials or
request bytes; that transport remains busy until its connection attempt exits.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import ipaddress
import math
import re
import socket
import ssl
import threading
import time
from typing import Callable


DEEPSEEK_ENDPOINT = "https://api.deepseek.com/chat/completions"
MAX_RESPONSE_BYTES = 256 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 30


class SemanticTransportError(Exception):
    """A fixed safe code; never the original exception or provider response."""

    def __init__(self, code: str):
        self.code = code if type(code) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "transport_error"
        super().__init__(self.code)


@dataclass(frozen=True)
class TransportResponse:
    status: int
    body: bytes = field(repr=False)


class _HeaderReader:
    """Bound header/status lines, including interim responses and chunk framing."""

    def __init__(self, stream):
        self._stream = stream
        self._remaining = MAX_HEADER_BYTES

    def readline(self, limit=-1):
        maximum = self._remaining + 1
        if limit >= 0:
            maximum = min(maximum, limit)
        line = self._stream.readline(maximum)
        self._remaining -= len(line)
        if self._remaining < 0:
            raise SemanticTransportError("response_headers_too_large")
        return line

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _ResponseSocket:
    def __init__(self, sock):
        self._sock = sock

    def makefile(self, *args, **kwargs):
        return _HeaderReader(self._sock.makefile(*args, **kwargs))


class _BoundedResponse(http.client.HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        super().__init__(_ResponseSocket(sock), *args, **kwargs)


class DeepSeekTransport:
    """Fixed official origin. Endpoint changes are not a production option."""

    def __init__(self):
        self._host, self._port, self._tls = "api.deepseek.com", 443, True
        self._flight = threading.Lock()

    @classmethod
    def _loopback_for_test(cls, *, host: str, port: int):
        """Trusted wire tests only; reject names and every non-loopback address."""
        try:
            address = ipaddress.ip_address(host)
        except (TypeError, ValueError):
            raise ValueError("test transport requires a literal loopback address") from None
        if not address.is_loopback or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("test transport requires a literal loopback address and port")
        selected = cls()
        selected._host, selected._port, selected._tls = str(address), port, False
        return selected

    def _connection(self, timeout):
        if self._tls:
            # Build a verifying client context without create_default_context's
            # optional SSLKEYLOGFILE environment hook.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_default_certs()
            connection = http.client.HTTPSConnection(self._host, self._port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(self._host, self._port, timeout=timeout)
        connection.set_debuglevel(0)
        # send()/endheaders() otherwise reconnect implicitly if cancellation
        # closes the socket between a permission check and the actual write.
        connection.auto_open = 0
        connection.response_class = _BoundedResponse
        return connection

    def send(self, body: bytes, *, api_key: str, timeout_seconds: float,
             cancel_event: threading.Event, live_guard: Callable[[], None]) -> TransportResponse:
        if (type(body) is not bytes or not body or len(body) > MAX_REQUEST_BYTES
                or type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
                or not isinstance(cancel_event, threading.Event) or not callable(live_guard)):
            raise SemanticTransportError("invalid_request")
        if type(api_key) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,512}", api_key) is None:
            raise SemanticTransportError("invalid_api_key")
        if not self._flight.acquire(blocking=False):
            raise SemanticTransportError("transport_busy")
        deadline = time.monotonic() + timeout_seconds
        finished, stopped = threading.Event(), threading.Event()
        state_lock = threading.Lock()
        state = {"connection": None, "socket": None, "result": None, "error": None, "stop_code": None}

        def stop(code):
            with state_lock:
                if state["stop_code"] is None:
                    state["stop_code"] = code
                stopped.set()
                connection = state["connection"]
                active_socket = state["socket"]
            # shutdown interrupts file-buffered HTTPResponse reads as well as
            # sendall; close alone can leave the makefile descriptor alive.
            if connection is not None:
                sock = connection.sock or active_socket
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        sock.close()
                    except OSError:
                        pass
            # HTTPResponse.close()/HTTPConnection.close() can wait on another
            # thread's buffered read lock. The exchange thread owns that cleanup;
            # the cancellation caller only shuts down/closes the raw socket.

        def guard():
            if stopped.is_set():
                raise SemanticTransportError(state["stop_code"] or "cancelled")
            if cancel_event.is_set():
                raise SemanticTransportError("cancelled")
            if time.monotonic() >= deadline:
                raise SemanticTransportError("timeout")
            try:
                live_guard()
            except SemanticTransportError:
                raise
            except Exception:
                raise SemanticTransportError("authorization_changed") from None
            if stopped.is_set() or cancel_event.is_set():
                raise SemanticTransportError(state["stop_code"] or "cancelled")
            if time.monotonic() >= deadline:
                raise SemanticTransportError("timeout")

        def socket_timeout(connection):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SemanticTransportError("timeout")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)

        def exchange():
            connection = response = None
            try:
                guard()
                connection = self._connection(max(.001, deadline - time.monotonic()))
                with state_lock:
                    state["connection"] = connection
                guard()
                connection.connect()
                with state_lock:
                    state["socket"] = connection.sock
                # DNS/TCP/TLS completion is never permission to send later if
                # the caller has meanwhile cancelled, expired or revoked it.
                guard()
                socket_timeout(connection)
                connection.putrequest("POST", "/chat/completions", skip_accept_encoding=True)
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Accept", "application/json")
                connection.putheader("Accept-Encoding", "identity")
                connection.putheader("Authorization", "Bearer " + api_key)
                connection.putheader("Content-Length", str(len(body)))
                guard()
                connection.endheaders()
                guard()
                socket_timeout(connection)
                connection.send(body)
                guard()
                socket_timeout(connection)
                response = connection.getresponse()
                guard()
                if response.status != 200:
                    raise SemanticTransportError(f"http_{response.status}" if 100 <= response.status <= 599 else "http_error")
                if response.getheader("Content-Encoding", "identity").lower().strip() != "identity":
                    raise SemanticTransportError("unsupported_response_encoding")
                if response.length is not None and response.length > MAX_RESPONSE_BYTES:
                    raise SemanticTransportError("response_too_large")
                received = bytearray()
                while True:
                    guard()
                    socket_timeout(connection)
                    chunk = response.read(min(65536, MAX_RESPONSE_BYTES + 1 - len(received)))
                    guard()
                    if not chunk:
                        break
                    received.extend(chunk)
                    if len(received) > MAX_RESPONSE_BYTES:
                        raise SemanticTransportError("response_too_large")
                guard()
                with state_lock:
                    state["result"] = TransportResponse(200, bytes(received))
            except SemanticTransportError as error:
                with state_lock:
                    state["error"] = error.code
            except (TimeoutError, socket.timeout):
                with state_lock:
                    state["error"] = "timeout"
            except ssl.SSLError:
                with state_lock:
                    state["error"] = "tls_error"
            except http.client.HTTPException:
                with state_lock:
                    state["error"] = "invalid_response"
            except BaseException:
                # A background exception must not print credentials, request
                # bytes, provider content or an exception repr to stderr.
                with state_lock:
                    state["error"] = "network_error"
            finally:
                if response is not None:
                    try:
                        response.close()
                    except OSError:
                        pass
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass
                self._flight.release()
                finished.set()

        worker = threading.Thread(target=exchange, name="codesentry-deepseek-transport", daemon=True)
        try:
            worker.start()
        except Exception:
            self._flight.release()
            raise SemanticTransportError("network_error") from None
        try:
            while not finished.wait(min(.02, max(.001, deadline - time.monotonic()))):
                guard()
            guard()
            with state_lock:
                error, result = state["error"], state["result"]
            if error is not None:
                raise SemanticTransportError(error)
            if type(result) is not TransportResponse:
                raise SemanticTransportError("invalid_response")
            return result
        except SemanticTransportError as error:
            stop(error.code)
            raise SemanticTransportError(error.code) from None
        except BaseException:
            stop("cancelled")
            raise
