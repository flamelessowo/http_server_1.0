# IMPLEMENTATION OF OBSOLETE PROTOCOL HTTP/1.0 server (RECREATIONAL PROGRAMMING)
# The purpose is not writing "pretty" code but to understand, more or less, what is HTTP/1.0 about
# This implementation would serve static folder and i guess i'll add some custom router for post requests
# Also I ,sometimes, use old fashioned python to more or less deeply go into the problems
# Followed by RFC1945
# Interesting to implement: UDS, Params parsing, Template engine, Make this as python library(probably not)
# TODO proper error handling, proper uri syntax(RFC 1945 3.2), charsets(3.4), multipart (3.6.2)
import gzip
import logging
from dataclasses import dataclass
import re
import signal
import socket, struct
import os
import zlib
from error import error_with_html_page
from datetime import datetime, UTC
from argparse import ArgumentParser
from args import get_arg_parser
from enum import Enum

from constants import *

logging.basicConfig(level=logging.INFO)
shutdown_flag = False

def handle_sigint(signum, frame):
    global shutdown_flag
    logging.info("[!] Caught SIGINT, shutting down...")
    shutdown_flag = True

signal.signal(signal.SIGINT, handle_sigint)

#  HTTP/1.0 servers must:

#       o recognize the format of the Request-Line for HTTP/0.9 and
#         HTTP/1.0 requests;

#       o understand any valid request in the format of HTTP/0.9 or
#         HTTP/1.0;

#       o respond appropriately with a message in the same protocol
#         version used by the client.

http_version_regex = re.compile(r"^HTTP/(?P<major>%d{1})\.(?P<minor>%d{1})$")
#"GET /index.html HTTP/1.1\r\n"
request_line_regex = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/(?P<major>\d+)\.(?P<minor>\d+)$'
)
request_line_legacy_regex = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)'
)
status_line_regex = re.compile(
    r"^HTTP/(?P<major>\d+)\.(?P<minor>\d+)\s+(?P<code>\d{3})\s+(?P<reason>.*)$"
)

def compress_with_gzip(data: bytes) -> bytes:
    return gzip.compress(data)

def decompress_with_gzip(data: bytes) -> bytes:
    return gzip.decompress(data) 

def compress_with_zlib(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress_with_zlib(data: bytes) -> bytes:
    return zlib.decompress(data)

encodings_map = {
    "gzip": compress_with_gzip,
    "x-compress": compress_with_zlib
}

# date handling
dt_rfc1123 = "%a, %d %b %Y %H:%M:%S GMT"
dt_rfc850 = "%A, %d-%b-%y %H:%M:%S GMT"
dt_asctime = "%a %b %d %H:%M:%S %Y"

DATE_FORMATS = [dt_rfc1123, dt_rfc850, dt_asctime]

class HttpVersion(Enum):
    MAJOR_VERSION = 1
    MINOR_VERSION = 0
    REPR = "HTTP/1.0"

@dataclass
class RequestLine:
    method: str
    request_uri: str
    proto_ver: str

    def __str__(self) -> str:
        return f"{self.method} {self.request_uri} {self.proto_ver}{CRLF}"

@dataclass
class StatusLine:
    proto_ver: str
    status_code: int | None
    reason_phrase: str | None

    def format(self) -> str:
        return f"{self.proto_ver} {self.status_code} {self.reason_phrase}{CRLF}"

def prepare_server_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0) # set socket timeout so I can end program gracefully after SIGINT
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_DEBUG, 1)
    linger = struct.pack("ii", 1, 2) # little-endian i = unsigned int (4 bytes)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger) # Maybe sometimes can help with data loss
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) # Load balancing maybe in the future
    return sock

def prepare_response(status_line: StatusLine, headers: dict, body: bytes) -> bytes:
    encoded_status_line = status_line.format().encode()
    encoded_headers = b"".join([f"{key}: {value}{CRLF}".encode() for key, value in headers.items()])
    return encoded_status_line + encoded_headers + CRLF.encode() + body

def parse_http_request(buffer: bytes) -> tuple[RequestLine, dict, bytes]:
    header_part, body_part = buffer.split(HEADER_BODY_SPLIT.encode(), 1)

    request_headers = header_part.decode()
    splitted_request_headers = request_headers.split(CRLF)

    request_line: RequestLine = parse_request_line(splitted_request_headers[0])
    request_headers_dict: dict = parse_request_headers(splitted_request_headers[1:])
    return request_line, request_headers_dict, body_part

def parse_request_line(line: str) -> RequestLine:
    m = request_line_regex.match(line)

    return RequestLine(method=m.group("method"), request_uri=m.group("uri"), proto_ver=f"HTTP/{m.group('major')}.{m.group('minor')}")

def parse_request_headers(request_headers: list[str]) -> dict:
    headers = {}
    for line in request_headers:
        line = line.split(": ")
        headers[line[0].lower()] = line[1].strip() # http headers are case-insensetive
    return headers

def read_static_content(uri, ext="html") -> bytes:
    files = os.listdir(os.curdir + STATIC_FOLDER)
    buffer: str = ""

    if uri[1:] not in files:
        return None

    with open(os.curdir + STATIC_FOLDER + uri, "rb") as file:
        buffer = file.read()

    return buffer

def handle_get(line: RequestLine, headers: dict) -> bytes:
    file_ext = line.request_uri.split(".")[1]
    buffer = read_static_content(uri=line.request_uri, ext=file_ext)

    if buffer is None:
        return generate_error_response(StatusCode.NOT_FOUND.code, StatusCode.NOT_FOUND.reason, "Not found")

    logging.info("Serving client")
    resp_headers = {"Content-Type": ext_to_mime(file_ext), 
                    "Allow": "GET, HEAD", 
                    "Server": "DumbHTTP/1.0", 
                    "Date": datetime.now(UTC).strftime(dt_rfc1123)} # get_default_resp_headers
    # Handle encoding
    if "accept-encoding" in headers.keys():
        encodings = headers.get("accept-encoding", "gzip, x-compress").split(", ") # TODO make proper encodings handling
        buffer = encodings_map[encodings[0]](buffer) # Take first encoding, i guess there should be custom criteria for that, It doesn't matter in my case
        resp_headers["Content-Encoding"] = encodings[0]
    resp_headers["Content-Length"] = len(buffer)

    sl = StatusLine(proto_ver=HttpVersion.REPR.value, status_code=StatusCode.OK.code, reason_phrase=StatusCode.OK.reason)

    if line.request_uri[1:] in moved_resources:
        resp_headers["Location"] = moved_resources[line.request_uri[1:]]
        sl = StatusLine(proto_ver=HttpVersion.REPR.value, status_code=StatusCode.MOVED_PERMANENTLY, reason_phrase=StatusCode.MOVED_PERMANENTLY.reason)

    if line.method == "HEAD":
        return prepare_response(sl, resp_headers, b"")

    return prepare_response(sl, resp_headers, buffer)

def generate_error_response(status_code: int, reason: str, explain: str, *, ext="html") -> bytes:
    line = StatusLine(HttpVersion.REPR.value, status_code, reason)
    buffer: bytes = error_with_html_page(status_code, reason, explain).encode()
    resp_headers = {"Content-Type": ext_to_mime(ext), 
                    "Server": "DumbHTTP/1.0", 
                    "Date": datetime.now().strftime(dt_rfc1123), 
                    "Content-Length": len(buffer)}
    response: bytes = prepare_response(line, resp_headers, buffer)
    return response

# Should accept GET, POST, HEAD RFC 1945 (8. Method Definitions)
def handle_http_request(cli_sock: socket.socket, line: RequestLine, headers: dict, body: bytes = b"") -> None:
    response = ""
    if line.method not in ["GET", "HEAD", "POST"]:
        response: bytes = generate_error_response(StatusCode.BAD_REQUEST.code, 
                                                  StatusCode.BAD_REQUEST.reason, 
                                                  "Only [GET, HEAD] requests are supported")
        cli_sock.send(response)
        return
    
    if line.method == "POST":
        response: bytes = generate_error_response(StatusCode.NOT_IMPLEMENTED.code, 
                                                  StatusCode.NOT_IMPLEMENTED.reason, 
                                                  "POST requests are not supported!")
        cli_sock.send(response)
        return

    response = handle_get(line, headers)
    cli_sock.send(response)

def handle_simple_http_request(cli_sock: socket.socket, buffer: bytes):
    line = buffer.decode()
    m = request_line_legacy_regex.match(line)
    uri = m.group("uri")
    buffer = read_static_content(uri)
    cli_sock.send(buffer)

if __name__ == "__main__":
    moved_resources = {"resource_moved.html": "new_resource.html"}
    parser: ArgumentParser = get_arg_parser()
    parser.parse_args()
    # phase 1 setup socket
    sock = prepare_server_socket()
    sock.bind((DEFAULT_HOST, DEFAULT_PORT))
    sock.listen(54)
    while not shutdown_flag:
        try:
            logging.info("Waiting for clients")
            cli_sock, addr = sock.accept()
            logging.info(f"Connected: {addr}")
            buffer = b""
            legacy = False

            while bytes(HEADER_BODY_SPLIT.encode()) not in buffer:
                chunk = cli_sock.recv(4096)
                if not chunk:
                    req_line = buffer.split(CRLF.encode(), 1)[0]
                    m = request_line_legacy_regex.match(req_line.decode())
                    if m:
                        logging.info("Detected simple HTTP/0.9 request")
                        legacy = True
                        break
                    raise ConnectionError("Connection closed before headers were received")
                buffer += chunk
            logging.info("Read request")

            if legacy:
                handle_simple_http_request(cli_sock, buffer)
            else:
                request_line, request_headers_dict, body_part = parse_http_request(buffer)
                handle_http_request(cli_sock, line=request_line, headers=request_headers_dict, body=body_part)
            logging.info("Finished serving")
            cli_sock.close()
            logging.info("Closed connection")
        except socket.timeout:
            pass

    sock.close()
    try:
        cli_sock.close()
    except Exception:
        pass
