from enum import StrEnum
from .mime_types import MimeType, ext_to_mime
from .status_codes import StatusCode

class RequestMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5469
STATIC_FOLDER = "/static"

CRLF = "\r\n"
HEADER_BODY_SPLIT = CRLF * 2