# IMPLEMENTATION OF OBSOLETE PROTOCOL HTTP/1.0 server (RECREATIONAL PROGRAMMING)
# The purpose is not writing "pretty" code but to understand, more or less, what is HTTP/1.0 about
# Followed by RFC1945
# Interesting to implement: UDS
from dataclasses import dataclass
import re
import socket
from constants import *
from argparse import ArgumentParser
from args import get_arg_parser
from enum import Enum

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

status_line_regex = re.compile(
    r"^HTTP/(?P<major>\d+)\.(?P<minor>\d+)\s+(?P<code>\d{3})\s+(?P<reason>.*)$"
)

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
        return f"{self.method} {self.request_uri} {self.proto_ver}"

@dataclass
class StatusLine:
    proto_ver: str
    status_code: int | None
    reason_phrase: str | None

    def __str__(self) -> str:
        return f"{self.proto_ver} {self.status_code} {self.reason_phrase}"

def parse_request_line(line: str):
    m = request_line_regex.match(line)

    return RequestLine(method=m.group("method"), request_uri=m.group("uri"), proto_ver=f"HTTP/{m.group('major')}.{m.group('minor')}")

def parse_request_headers(request_headers: list[str]):
    headers = {}
    for line in request_headers:
        line = line.split(": ")
        headers[line[0].lower()] = line[1].strip() # http headers are case-insensetive
    return headers


if __name__ == "__main__":
    parser: ArgumentParser = get_arg_parser()
    parser.parse_args()
    # phase 1 setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((DEFAULT_HOST, DEFAULT_PORT))
    sock.listen(54)
    while True:
        cli_sock, addr = sock.accept()
        buffer = b""
        while bytes(HEADER_BODY_SPLIT.encode()) not in buffer:
            chunk = cli_sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed before headers were received")
            buffer += chunk
        header_part, body_part = buffer.split(bytes(HEADER_BODY_SPLIT.encode()), 1)

        request_headers = header_part.decode()
        splitted_request_headers = request_headers.split(CRLF)

        request_line: RequestLine = parse_request_line(splitted_request_headers[0])
        print(splitted_request_headers)
        request_headers_dict: dict = parse_request_headers(splitted_request_headers[1:])
        print(request_line)
        print(request_headers_dict)
        cli_sock.shutdown(socket.SHUT_WR)
        cli_sock.close()

    sock.shutdown(socket.SHUT_WR)
    sock.close()
    exit(0)