# ---------------------------------------------------------------------------
# ESP8266 Communication Helpers
# ---------------------------------------------------------------------------
def _esp_request_with_retry(method: str, endpoint: str, max_retries: int = 3) -> requests.Response:
    """Make request to ESP8266 with exponential backoff retry logic."""
    import requests
    url = f"http://{config.ESP_IP}:{config.ESP_HTTP_PORT}/{endpoint.lstrip('/')}"
    
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, timeout=5)
            response.raise_for_status()
            return response
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            backoff_time = 0.1 * (2 ** attempt)  # Exponential backoff: 100ms, 200ms, 400ms
            log.warning(f"ESP request failed (attempt {attempt + 1}/{max_retries}), retrying in {backoff_time*1000:.0f}ms: {e}")
            time.sleep(backoff_time)
    
    raise RuntimeError("Max retries exceeded for ESP request")


def get_esp_status() -> Dict[str, Any]:
    """Get ESP8266 hardware status from its /status endpoint."""
    try:
        response = _esp_request_with_retry("GET", "/status")
        return response.json()
    except Exception as e:
        log.warning(f"Failed to get ESP status after retries: {e}")
        return {"status": "error", "error": str(e)}


def send_esp_open_command() -> bool:
    """Send open command to ESP8266 to trigger relay."""
    try:
        _esp_request_with_retry("POST", "/open")
        log.info("Successfully sent open command to ESP8266")
        return True
    except Exception as e:
        log.error(f"Failed to send open command to ESP8266 after retries: {e}")
        return False