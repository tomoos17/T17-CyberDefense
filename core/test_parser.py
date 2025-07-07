from log_parser import parse_log

log1 = "Failed login from 192.168.0.101 via SSH"
log2 = "Accepted login from 10.0.0.22 over HTTP"

print("Log 1:", parse_log(log1))
print("Log 2:", parse_log(log2))
