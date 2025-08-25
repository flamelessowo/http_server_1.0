from enum import StrEnum

class StatusCode(StrEnum):
    # 2xx Success
    OK = "200 OK"
    CREATED = "201 Created"
    ACCEPTED = "202 Accepted"
    NO_CONTENT = "204 No Content"

    # 3xx Redirection
    MULTIPLE_CHOICES = "300 Multiple Choices"
    MOVED_PERMANENTLY = "301 Moved Permanently"
    MOVED_TEMPORARILY = "302 Moved Temporarily"
    NOT_MODIFIED = "304 Not Modified"

    # 4xx Client Error
    BAD_REQUEST = "400 Bad Request"
    UNAUTHORIZED = "401 Unauthorized"
    FORBIDDEN = "403 Forbidden"
    NOT_FOUND = "404 Not Found"

    # 5xx Server Error
    INTERNAL_SERVER_ERROR = "500 Internal Server Error"
    NOT_IMPLEMENTED = "501 Not Implemented"
    BAD_GATEWAY = "502 Bad Gateway"
    SERVICE_UNAVAILABLE = "503 Service Unavailable"

    @property
    def code(self) -> int:
        return int(self.value.split()[0])

    @property
    def reason(self) -> str:
        return " ".join(self.value.split()[1:])
