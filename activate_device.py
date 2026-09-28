#!/usr/bin/env python3
"""
iOS Device Activation Client - FIXED + Production Hardening
- Correctly base64-encodes activation-info for form submission
- Handles session mode handshake properly
- Fixes headers and error handling
- Production hardening: timeouts/retries (tenacity with fallback, exponential backoff),
  structured logging with request_id, input validation UDID/IMEI, --json output, X-Request-ID header, 413/429 handling
  circuit breaker per base_url (open after 5 failures for 30s, 503 + X-Circuit-Breaker)
"""
import asyncio
import argparse
import logging
import plistlib
import base64
import requests
import os
import re
import json
import uuid
import time
from typing import Optional, Dict, Any, Tuple

try:
    from pymobiledevice3.lockdown import LockdownClient
    from pymobiledevice3.services.mobile_activation import MobileActivationService
    from pymobiledevice3.usbmux import list_devices
    PYMOBILEDEVICE3_AVAILABLE = True
except ImportError:
    PYMOBILEDEVICE3_AVAILABLE = False
    print("Warning: pymobiledevice3 not available. Install with: pip install pymobiledevice3")

try:
    from libimobiledevice import idevice, lockdownd, mobileactivation
    LIBIMOBILEDEVICE_AVAILABLE = True
except ImportError:
    LIBIMOBILEDEVICE_AVAILABLE = False
    pass

# --- Tenacity import with fallback ---
try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
    TENACITY_AVAILABLE = True
except ImportError:
    TENACITY_AVAILABLE = False

    def retry(*dargs, **dkw):
        def decorator(func):
            return func
        return decorator

    def stop_after_attempt(n):
        return None

    def wait_exponential(*args, **kwargs):
        return None

    def retry_if_exception_type(exc):
        return None

# --- Circuit breaker: in-memory FAIL_COUNT per base_url, open after 5 failures for 30s, return 503 + header X-Circuit-Breaker ---
FAIL_COUNT: Dict[str, int] = {}
_CIRCUIT_OPENED_AT: Dict[str, float] = {}
CIRCUIT_THRESHOLD = 5
CIRCUIT_TIMEOUT = 30  # seconds
import threading as _cb_threading
_circuit_lock = _cb_threading.Lock()

def _is_circuit_open(base_url: str) -> bool:
    with _circuit_lock:
        opened = _CIRCUIT_OPENED_AT.get(base_url)
        if opened is None:
            return False
        if time.time() - opened < CIRCUIT_TIMEOUT:
            return True
        # timeout expired -> half-open, reset
        FAIL_COUNT.pop(base_url, None)
        _CIRCUIT_OPENED_AT.pop(base_url, None)
        return False

def _record_failure(base_url: str) -> None:
    with _circuit_lock:
        cnt = FAIL_COUNT.get(base_url, 0) + 1
        FAIL_COUNT[base_url] = cnt
        if cnt >= CIRCUIT_THRESHOLD:
            _CIRCUIT_OPENED_AT[base_url] = time.time()

def _record_success(base_url: str) -> None:
    with _circuit_lock:
        FAIL_COUNT.pop(base_url, None)
        _CIRCUIT_OPENED_AT.pop(base_url, None)

def _reset_circuit_breaker(base_url: str = None) -> None:
    with _circuit_lock:
        if base_url is not None:
            FAIL_COUNT.pop(base_url, None)
            _CIRCUIT_OPENED_AT.pop(base_url, None)
        else:
            FAIL_COUNT.clear()
            _CIRCUIT_OPENED_AT.clear()

def _circuit_open_response(url: str) -> requests.Response:
    resp = requests.Response()
    resp.status_code = 503
    resp.headers["X-Circuit-Breaker"] = "open"
    resp._content = b'{"error": "circuit breaker open"}'
    resp.url = url
    resp.reason = "Circuit Breaker Open"
    return resp

def _tenacity_retry_error_callback(retry_state) -> None:
    # Called when tenacity retries exhausted (kept for spec compliance, used as retry_error_callback if needed)
    try:
        self_obj = retry_state.args[0] if retry_state.args else None
        base_url = getattr(self_obj, 'base_url', None) if self_obj else None
        if base_url:
            _record_failure(base_url)
    except Exception:
        pass
    return None

def _handle_tenacity_retry_error(func):
    """Wrapper to convert tenacity RetryError into None and record circuit failure."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Handle tenacity RetryError (when reraise=False)
            try:
                from tenacity import RetryError
                if isinstance(e, RetryError):
                    self_obj = args[0] if args else None
                    base_url = getattr(self_obj, 'base_url', None) if self_obj else None
                    if base_url:
                        _record_failure(base_url)
                    return None
            except ImportError:
                pass
            # Handle direct ConnectionError/TimeoutError after retries (when reraise=True)
            if isinstance(e, (ConnectionError, TimeoutError)):
                self_obj = args[0] if args else None
                base_url = getattr(self_obj, 'base_url', None) if self_obj else None
                if base_url:
                    _record_failure(base_url)
                return None
            raise
    return wrapper

# --- Structured logging with request_id ---
class RequestIdFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, 'request_id'):
            record.request_id = '-'
        return True

_request_id_filter = RequestIdFilter()
_json_available = False
try:
    from pythonjsonlogger import jsonlogger  # type: ignore
    _handler = logging.StreamHandler()
    _formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s",
        rename_fields={"levelname": "level", "asctime": "timestamp"},
    )
    _handler.setFormatter(_formatter)
    _handler.addFilter(_request_id_filter)
    root_logger = logging.getLogger()
    if root_logger.handlers:
        for h in list(root_logger.handlers):
            root_logger.removeHandler(h)
    root_logger.addHandler(_handler)
    root_logger.setLevel(logging.INFO)
    _json_available = True
except Exception:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s')
    for h in logging.getLogger().handlers:
        h.addFilter(_request_id_filter)

logger = logging.getLogger(__name__)
logger.addFilter(_request_id_filter)

DEFAULT_ALBERT_URL = "http://127.0.0.1:8080"
ALBERT_ENDPOINTS = {
    "drm_handshake": "/deviceservices/drmHandshake",
    "device_activation": "/deviceservices/deviceActivation",
}

# --- Input validation (P2) ---
_IMEI_RE = re.compile(r"^\d{15}$")
_UDID_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_UDID_25_RE = re.compile(r"^00008020-[0-9a-fA-F]{16}$")

def _validate_imei(v) -> bool:
    if v is None or v == "":
        return True
    return bool(_IMEI_RE.fullmatch(str(v).strip()))

def _validate_udid(v) -> bool:
    if v is None or v == "":
        return True
    s = str(v).strip()
    if _UDID_40_RE.fullmatch(s):
        return True
    if _UDID_25_RE.fullmatch(s):
        return True
    return False

def _validate_inputs(udid: Optional[str] = None, imei: Optional[str] = None) -> None:
    errors = []
    if udid is not None and udid != "" and not _validate_udid(udid):
        errors.append(f"Invalid UDID: {udid!r} must be 40 hex or 00008020-<16 hex>")
    if imei is not None and imei != "" and not _validate_imei(imei):
        errors.append(f"Invalid IMEI: {imei!r} must be 15 digits")
    if errors:
        raise ValueError("; ".join(errors))

# --- Retry / timeout constants ---
DEFAULT_TIMEOUT = 10  # seconds per request
MAX_RETRIES = 3  # retries = 3 attempts with exponential backoff (1s,2s,4s)
BACKOFF_FACTOR = 1.0  # base seconds

class LocalAlbertClient:
    def __init__(self, base_url: str = DEFAULT_ALBERT_URL, timeout: int = DEFAULT_TIMEOUT, max_retries: int = MAX_RETRIES):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "iOS Device Activator (MobileActivation-592.103.2)",
            "Accept": "application/xml",
        })

    def _generate_request_id(self) -> str:
        return str(uuid.uuid4())

    # Wire tenacity + manual 429 handling; try import tenacity else fallback
    # Required decorator: @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8), retry=retry_if_exception_type((ConnectionError, TimeoutError)))
    # plus manual 429 handling inside
    @_handle_tenacity_retry_error
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8), retry=retry_if_exception_type((ConnectionError, TimeoutError))) if TENACITY_AVAILABLE else lambda f: f
    def _post_with_retry(self, url: str, data, headers: Dict[str, str], request_id: str) -> Optional[requests.Response]:
        """POST with tenacity (if available) + manual exponential backoff for 429/5xx + circuit breaker. Returns Response or None, or 503 if circuit open."""
        # Circuit breaker check at entry
        if _is_circuit_open(self.base_url):
            logger.warning(f"Circuit breaker open for {self.base_url} request_id={request_id} returning 503", extra={"request_id": request_id})
            return _circuit_open_response(url)

        # Ensure X-Request-ID header
        headers = dict(headers)
        headers["X-Request-ID"] = request_id
        last_exc = None
        for attempt in range(self.max_retries):
            try:
                logger.info(f"POST {url} attempt {attempt+1}/{self.max_retries}", extra={"request_id": request_id})
                response = self.session.post(url, data=data, headers=headers, timeout=self.timeout)
                # Handle 413/429 specifically before raise_for_status
                if response.status_code == 413:
                    logger.error(f"Payload too large (413) for {url} request_id={request_id} response: {response.text[:500]}", extra={"request_id": request_id})
                    _record_failure(self.base_url)
                    return None
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    wait = BACKOFF_FACTOR * (2 ** attempt)
                    if retry_after:
                        try:
                            wait = max(wait, int(retry_after))
                        except ValueError:
                            pass
                    logger.warning(f"Rate limited (429) for {url} request_id={request_id} retry_after={retry_after} attempt={attempt+1}", extra={"request_id": request_id})
                    if attempt < self.max_retries - 1:
                        time.sleep(wait)
                        continue
                    else:
                        logger.error(f"Rate limit exceeded after {self.max_retries} attempts request_id={request_id}", extra={"request_id": request_id})
                        _record_failure(self.base_url)
                        return None
                # For 5xx, retry
                if 500 <= response.status_code < 600:
                    logger.warning(f"Server error {response.status_code} for {url} request_id={request_id} attempt={attempt+1}", extra={"request_id": request_id})
                    if attempt < self.max_retries - 1:
                        wait = BACKOFF_FACTOR * (2 ** attempt)
                        time.sleep(wait)
                        continue
                    else:
                        try:
                            response.raise_for_status()
                        except Exception as e:
                            last_exc = e
                        _record_failure(self.base_url)
                        return None
                response.raise_for_status()
                logger.info(f"POST {url} succeeded status={response.status_code} request_id={request_id}", extra={"request_id": request_id})
                _record_success(self.base_url)
                return response
            except requests.exceptions.Timeout as e:
                last_exc = e
                logger.warning(f"Timeout for {url} attempt {attempt+1}/{self.max_retries} request_id={request_id}: {e}", extra={"request_id": request_id})
                if TENACITY_AVAILABLE:
                    # Convert to builtin for tenacity retry
                    raise TimeoutError(str(e)) from e
                if attempt < self.max_retries - 1:
                    wait = BACKOFF_FACTOR * (2 ** attempt)
                    time.sleep(wait)
                    continue
                else:
                    logger.error(f"Timeout after {self.max_retries} attempts for {url} request_id={request_id}", extra={"request_id": request_id})
                    _record_failure(self.base_url)
                    return None
            except requests.exceptions.ConnectionError as e:
                last_exc = e
                logger.warning(f"Connection error for {url} attempt {attempt+1}/{self.max_retries} request_id={request_id}: {e}", extra={"request_id": request_id})
                if TENACITY_AVAILABLE:
                    raise ConnectionError(str(e)) from e
                if attempt < self.max_retries - 1:
                    wait = BACKOFF_FACTOR * (2 ** attempt)
                    time.sleep(wait)
                    continue
                else:
                    logger.error(f"Connection failed after {self.max_retries} attempts for {url} request_id={request_id}", extra={"request_id": request_id})
                    _record_failure(self.base_url)
                    return None
            except (ConnectionError, TimeoutError) as e:
                # Builtin exceptions (from tenacity path or direct)
                last_exc = e
                logger.warning(f"Connection/Timeout (builtin) for {url} attempt {attempt+1}/{self.max_retries} request_id={request_id}: {e}", extra={"request_id": request_id})
                if TENACITY_AVAILABLE:
                    # Let tenacity handle retry; re-raise
                    raise
                if attempt < self.max_retries - 1:
                    wait = BACKOFF_FACTOR * (2 ** attempt)
                    time.sleep(wait)
                    continue
                else:
                    logger.error(f"Failed after {self.max_retries} attempts for {url} request_id={request_id}: {e}", extra={"request_id": request_id})
                    _record_failure(self.base_url)
                    return None
            except requests.exceptions.HTTPError as e:
                # Already handled 413/429/5xx, other 4xx are not retryable
                logger.error(f"HTTP error for {url} request_id={request_id}: {e} status={getattr(e.response, 'status_code', '?')}", extra={"request_id": request_id})
                if hasattr(e, 'response') and getattr(e, 'response', None) is not None:
                    try:
                        logger.error(f"Response: {e.response.text[:500]}", extra={"request_id": request_id})
                    except Exception:
                        pass
                _record_failure(self.base_url)
                return None
            except Exception as e:
                last_exc = e
                logger.error(f"Unexpected error for {url} request_id={request_id}: {e}", extra={"request_id": request_id})
                if attempt < self.max_retries - 1:
                    wait = BACKOFF_FACTOR * (2 ** attempt)
                    time.sleep(wait)
                    continue
                else:
                    _record_failure(self.base_url)
                    return None
        if last_exc:
            logger.error(f"All retries exhausted for {url} request_id={request_id}: {last_exc}", extra={"request_id": request_id})
            _record_failure(self.base_url)
        return None
    def drm_handshake(self, collection_blob: bytes, handshake_msg: bytes, udid: str) -> Optional[bytes]:
        request_id = self._generate_request_id()
        # Input validation for UDID before call
        try:
            _validate_inputs(udid=udid)
        except ValueError as e:
            logger.error(f"Input validation failed for drm_handshake udid={udid!r} request_id={request_id}: {e}", extra={"request_id": request_id})
            raise
        request_data = {
            "CollectionBlob": collection_blob,
            "HandshakeRequestMessage": handshake_msg,
            "UniqueDeviceID": udid,
        }
        plist_data = plistlib.dumps(request_data)
        url = f"{self.base_url}{ALBERT_ENDPOINTS['drm_handshake']}"
        headers = {
            "Content-Type": "application/x-apple-plist",
            "Accept": "application/xml",
        }
        response = self._post_with_retry(url, data=plist_data, headers=headers, request_id=request_id)
        if response is not None:
            logger.info("DRM handshake successful", extra={"request_id": request_id})
            # Log X-Request-ID echo if present
            resp_rid = response.headers.get("X-Request-ID", request_id)
            logger.debug(f"Handshake response X-Request-ID={resp_rid}", extra={"request_id": request_id})
            return response.content
        else:
            logger.error(f"DRM handshake failed after retries request_id={request_id}", extra={"request_id": request_id})
            return None

    def activate_device(self, activation_info: Dict[str, Any], session_mode: bool = False,
                        handshake_response: Optional[bytes] = None) -> Tuple[Optional[bytes], Optional[Dict]]:
        """Activate device with local Albert server - FIXED: base64 encodes plist"""
        request_id = self._generate_request_id()
        # Input validation for UDID/IMEI before call
        try:
            udid_val = activation_info.get("UniqueDeviceID") or activation_info.get("UDID")
            imei_val = activation_info.get("InternationalMobileEquipmentIdentity") or activation_info.get("IMEI")
            # Also check alternate keys
            if not udid_val:
                udid_val = activation_info.get("UniqueDeviceID")
            _validate_inputs(udid=udid_val, imei=imei_val)
        except ValueError as e:
            logger.error(f"Input validation failed for activate_device request_id={request_id}: {e}", extra={"request_id": request_id})
            raise

        # FIX: properly base64 encode the plist bytes
        activation_plist = plistlib.dumps(activation_info)
        activation_b64 = base64.b64encode(activation_plist).decode()

        if session_mode and handshake_response:
            if isinstance(handshake_response, bytes):
                try:
                    hp_b64 = base64.b64encode(handshake_response).decode()
                except Exception:
                    hp_b64 = handshake_response.decode(errors='ignore')
            else:
                hp_b64 = handshake_response
            activation_request = {
                "InStoreActivation": "false",
                "AppleSerialNumber": activation_info.get("SerialNumber", activation_info.get("SerialNumber", "")),
                "activation-info": activation_b64,
                "FairPlayHandshakeResponse": hp_b64,
            }
            for key, lockdown_key in [
                ("IMEI", "InternationalMobileEquipmentIdentity"),
                ("MEID", "MobileEquipmentIdentifier"),
                ("IMSI", "InternationalMobileSubscriberIdentity"),
                ("ICCID", "IntegratedCircuitCardIdentity"),
            ]:
                if lockdown_key in activation_info:
                    activation_request[key] = activation_info[lockdown_key]
                elif key in activation_info:
                    activation_request[key] = activation_info[key]
        else:
            activation_request = {
                "activation-info": activation_b64,
            }

        url = f"{self.base_url}{ALBERT_ENDPOINTS['device_activation']}"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
        }
        response = self._post_with_retry(url, data=activation_request, headers=headers, request_id=request_id)
        if response is not None:
            logger.info("Device activation successful", extra={"request_id": request_id})
            return response.content, dict(response.headers)
        else:
            logger.error(f"Device activation failed after retries request_id={request_id}", extra={"request_id": request_id})
            return None, None


async def activate_with_pymobiledevice3(udid: Optional[str], albert_url: str, 
                                         skip_apple_id: bool = False) -> bool:
    if not PYMOBILEDEVICE3_AVAILABLE:
        logger.error("pymobiledevice3 not available", extra={"request_id": "-"})
        return False
    # Validate UDID before proceeding
    if udid:
        try:
            _validate_inputs(udid=udid)
        except ValueError as e:
            logger.error(f"Input validation failed for UDID {udid!r}: {e}", extra={"request_id": "-"})
            print(json.dumps({"success": False, "error": str(e), "request_id": "-"}))
            return False
    try:
        devices = await list_devices()
        if not devices:
            logger.error("No devices found - connect via USB and ensure usbmuxd is running", extra={"request_id": "-"})
            return False
        if udid:
            device = next((d for d in devices if d.udid == udid), None)
            if not device:
                logger.error(f"Device with UDID {udid} not found. Available: {[d.udid for d in devices]}", extra={"request_id": "-"})
                return False
        else:
            device = devices[0]
        logger.info(f"Connecting to device: {device.udid}", extra={"request_id": "-"})
        lockdown = LockdownClient(device.udid)
        activation_service = MobileActivationService(lockdown)
        state = await activation_service.state()
        logger.info(f"Device activation state: {state}", extra={"request_id": "-"})
        if state == "Activated":
            logger.info("Device is already activated", extra={"request_id": "-"})
            return True
        logger.info("Attempting activation (requires proxy to redirect to local server)...", extra={"request_id": "-"})
        logger.warning("For local Albert server, ensure mitmproxy redirects albert.apple.com to %s or use http proxy settings", albert_url, extra={"request_id": "-"})
        try:
            await activation_service.activate(skip_apple_id_query=skip_apple_id)
            logger.info("Activation completed successfully!", extra={"request_id": "-"})
            return True
        except Exception as e:
            logger.error(f"Activation failed: {e}", extra={"request_id": "-"})
            return False
    except Exception as e:
        logger.error(f"Error during activation: {e}", exc_info=True, extra={"request_id": "-"})
        return False

def activate_with_libimobiledevice(udid: Optional[str], albert_url: str) -> bool:
    if not LIBIMOBILEDEVICE_AVAILABLE:
        logger.error("libimobiledevice Python bindings not available", extra={"request_id": "-"})
        return False
    logger.info("libimobiledevice activation via CLI tools recommended", extra={"request_id": "-"})
    return False

def activate_with_ideviceactivation(udid: Optional[str], albert_url: str) -> bool:
    import subprocess
    if udid:
        try:
            _validate_inputs(udid=udid)
        except ValueError as e:
            logger.error(f"Input validation failed for UDID {udid!r}: {e}", extra={"request_id": "-"})
            return False
    cmd = ["ideviceactivation"]
    if udid:
        cmd.extend(["-u", udid])
    env = {**os.environ, "ALBERT_URL": albert_url, "ALBERT_HOST": albert_url}
    try:
        logger.info(f"Running: {' '.join(cmd)} with ALBERT_URL={albert_url}", extra={"request_id": "-"})
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            logger.info("Activation successful!", extra={"request_id": "-"})
            logger.info(result.stdout, extra={"request_id": "-"})
            return True
        else:
            logger.error(f"Activation failed: {result.stderr}", extra={"request_id": "-"})
            logger.error(result.stdout, extra={"request_id": "-"})
            return False
    except subprocess.TimeoutExpired:
        logger.error("Activation timed out", extra={"request_id": "-"})
        return False
    except FileNotFoundError:
        logger.error("ideviceactivation not found. Install libimobiledevice-tools", extra={"request_id": "-"})
        return False
    except Exception as e:
        logger.error(f"Error running ideviceactivation: {e}", extra={"request_id": "-"})
        return False

async def get_device_info(udid: Optional[str]) -> Optional[Dict[str, Any]]:
    if not PYMOBILEDEVICE3_AVAILABLE:
        return None
    try:
        devices = await list_devices()
        if not devices:
            return None
        device = next((d for d in devices if d.udid == udid), devices[0]) if udid else devices[0]
        lockdown = LockdownClient(device.udid)
        info = {}
        for key in ["SerialNumber", "UniqueDeviceID", "ProductType", "ProductVersion",
                    "InternationalMobileEquipmentIdentity", "MobileEquipmentIdentifier",
                    "InternationalMobileSubscriberIdentity", "IntegratedCircuitCardIdentity",
                    "TelephonyCapability", "ActivationState", "BuildVersion", "ProductVersion"]:
            try:
                value = lockdown.get_value(key=key)
                if value:
                    info[key] = value
            except:
                pass
        try:
            all_vals = lockdown.all_values
            for k in ["DeviceName","TimeZone","Language"]:
                if k in all_vals and k not in info:
                    info[k] = all_vals[k]
        except:
            pass
        return info
    except Exception as e:
        logger.error(f"Error getting device info: {e}", extra={"request_id": "-"})
        return None

async def main():
    parser = argparse.ArgumentParser(description="iOS Device Activation Client (Fixed)")
    parser.add_argument("--udid", help="Device UDID (optional, uses first device if not specified)")
    parser.add_argument("--albert-url", default=DEFAULT_ALBERT_URL, 
                        help=f"Local Albert server URL (default: {DEFAULT_ALBERT_URL})")
    parser.add_argument("--skip-apple-id", action="store_true",
                        help="Skip Apple ID prompt (treat as iCloud lock)")
    parser.add_argument("--method", choices=["pymobiledevice3", "ideviceactivation", "direct", "auto"],
                        default="auto", help="Activation method to use")
    parser.add_argument("--info", action="store_true", help="Show device info only")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output results as JSON")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=MAX_RETRIES, help=f"Max retries with exponential backoff (default: {MAX_RETRIES})")
    args = parser.parse_args()

    # Validate UDID/IMEI before call if provided
    if args.udid:
        try:
            _validate_inputs(udid=args.udid)
        except ValueError as e:
            msg = f"Input validation failed: {e}"
            logger.error(msg, extra={"request_id": "-"})
            if args.json_output:
                print(json.dumps({"success": False, "error": msg, "request_id": "-"}))
            else:
                print(msg)
            exit(1)

    if args.info:
        info = await get_device_info(args.udid)
        if info:
            if args.json_output:
                print(json.dumps({"success": True, "info": info}, indent=2))
            else:
                for key, value in info.items():
                    print(f"{key}: {value}")
        else:
            if args.json_output:
                print(json.dumps({"success": False, "error": "Failed to get device info - no device connected or usbmuxd not running"}))
            else:
                print("Failed to get device info - no device connected or usbmuxd not running")
                print("Check: idevice_id -l  and  lsusb | grep -i apple")
        return
    logger.info(f"Using Albert server: {args.albert_url}", extra={"request_id": "-"})
    if args.method == "direct":
        # Validate UDID before direct call
        fake_udid = args.udid or "00008020-AAAAAAAAAAAAAAAA"
        try:
            _validate_inputs(udid=fake_udid, imei="350000000000006")
        except ValueError as e:
            msg = f"Input validation failed: {e}"
            logger.error(msg, extra={"request_id": "-"})
            if args.json_output:
                print(json.dumps({"success": False, "error": msg, "request_id": "-"}))
            else:
                print(msg)
            exit(1)
        client = LocalAlbertClient(args.albert_url, timeout=args.timeout, max_retries=args.retries)
        fake_info = {
            "DeviceClass": "iPhone",
            "UniqueDeviceID": fake_udid,
            "SerialNumber": "REDACTEDSERIAL",
            "ProductType": "iPhone11,8",
            "InternationalMobileEquipmentIdentity": "350000000000006",
            "MobileEquipmentIdentifier": "35000000000006",
            "ActivationRandomness": str(__import__('uuid').uuid4()),
        }
        try:
            data, headers = client.activate_device(fake_info)
        except ValueError as e:
            if args.json_output:
                print(json.dumps({"success": False, "error": str(e), "request_id": "-"}))
            else:
                print(f"Validation error: {e}")
            exit(1)
        if data:
            if args.json_output:
                # Try to parse plist for JSON output
                try:
                    resp = plistlib.loads(data)
                    # Convert bytes values to base64 for JSON serialization
                    def _serialize(obj):
                        if isinstance(obj, bytes):
                            return base64.b64encode(obj).decode()
                        return str(obj)
                    # Flatten top-level keys
                    json_resp = {k: _serialize(v) if isinstance(v, bytes) else v for k, v in resp.items()}
                    # Extract nested activation-record if present
                    print(json.dumps({
                        "success": True,
                        "response_length": len(data),
                        "response_keys": list(resp.keys()),
                        "headers": dict(headers) if headers else {},
                        "activation_response": json_resp,
                        "request_id": headers.get("X-Request-ID") if headers else None
                    }, indent=2))
                except Exception as e:
                    print(json.dumps({"success": True, "response_length": len(data), "raw_preview": base64.b64encode(data[:500]).decode(), "headers": dict(headers) if headers else {}, "parse_error": str(e)}))
            else:
                print("Direct activation test succeeded, response length", len(data))
                try:
                    resp = plistlib.loads(data)
                    print("Response keys:", list(resp.keys()))
                except Exception as e:
                    print("Response not plist:", e)
                    print(data[:500])
                if headers:
                    # Show X-Request-ID if echoed
                    rid = headers.get("X-Request-ID") or headers.get("x-request-id")
                    if rid:
                        print(f"X-Request-ID: {rid}")
        else:
            if args.json_output:
                print(json.dumps({"success": False, "error": "Direct activation failed", "request_id": "-"}))
            else:
                print("Direct activation failed")
        return
    if args.method == "auto":
        if PYMOBILEDEVICE3_AVAILABLE:
            args.method = "pymobiledevice3"
        else:
            args.method = "ideviceactivation"
    success = False
    if args.method == "pymobiledevice3":
        success = await activate_with_pymobiledevice3(args.udid, args.albert_url, args.skip_apple_id)
    elif args.method == "ideviceactivation":
        success = activate_with_ideviceactivation(args.udid, args.albert_url)
    if args.json_output:
        print(json.dumps({"success": success, "method": args.method, "albert_url": args.albert_url}))
    if success:
        logger.info("Device activated successfully!", extra={"request_id": "-"})
    else:
        logger.error("Activation failed!", extra={"request_id": "-"})
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())
