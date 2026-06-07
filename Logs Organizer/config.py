import re

# cores para terminal
class UI:
    RED    = '\033[31m'
    RESET = '\033[0m'
    B_BLUE = '\033[94m'
    B_YELLOW = '\033[93m'
    BOLD = '\033[1m'
    REVERSE = '\033[7m'
    B_MAGENTA = '\033[95m'

APACHE_DATETIME_REGEX = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]'

# linha syslog: DATETIME LEVEL service: message from IP PORT
SYSLOG_REGEX = re.compile(
    r'^(?P<datetime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+(?P<alert>INFO|WARNING|ERROR)'
    r'\s+(?P<service>\w+)\[\d+]:\s+'
    r'(?P<message>.+)'
)
IP_REGEX = re.compile(r'(\d{1,3}\.){3}\d{1,3}')

# linha Apache reformulada: IP - user DATETIME "request" LEVEL bytes
APACHE_REGEX = re.compile(
    r'^(?P<ip>(\d{1,3}\.){3}\d{1,3})'
    r'\s+-\s+\S+'
    r'\s+(?P<datetime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+"(?P<message>[^"]+)"'
    r'\s+(?P<alert>[2-5]\d{2})'
)
FAILED_PASSWORD = re.compile(r'Failed password')