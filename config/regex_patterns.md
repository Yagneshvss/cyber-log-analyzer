# Regex Patterns for Cyber Log Analyzer

# Username pattern
USERNAME = ^[a-zA-Z0-9._-]{1,64}$

# IPv4 address
IPV4 = ^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$

# Failed login indicators
LOGIN_FAIL = (?i)(invalid password|authentication failed|login failed|failed password)

# Suspicious user agents
SUSPICIOUS_UA = (?i)(curl|wget|python-requests|nikto|sqlmap)
