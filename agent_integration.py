"""
Integration Example for AI Agent

To use the HTTP Interceptor with your AI agent, add this at the start of your agent's main file:

```python
from http_interceptor import HTTPInterceptor, alert_handler

# Create interceptor with alert callback
interceptor = HTTPInterceptor(
    log_file='logs/agent_requests.jsonl',
    alert_callback=alert_handler
)

# Install hooks into common HTTP libraries
interceptor.install()

# Now all HTTP requests made via requests/httpx/urllib will be logged
# and scanned for sensitive data
```

Or use the decorator-based approach:

```python
from http_interceptor import http_intercept

# Wrap specific functions
@http_intercept
def make_api_call(url, api_key):
    import requests
    return requests.get(url, headers={'Authorization': f'Bearer {api_key}'})
```
"""

from http_interceptor import HTTPInterceptor, alert_handler

__all__ = ['HTTPInterceptor', 'alert_handler']

print("[*] HTTP Interceptor module loaded")
print("    To enable: interceptor = HTTPInterceptor(); interceptor.install()")
