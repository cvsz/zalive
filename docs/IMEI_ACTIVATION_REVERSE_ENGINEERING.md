# Deep Reverse Engineering: IMEI-Based Activation & Sync

## Overview

This document details the reverse engineering of iOS device activation flow, specifically how IMEI (International Mobile Equipment Identity) is used in the activation/synchronization process. Based on analysis of iPhone11,8 (iPhone XR) iOS 18.7.10 (22H374) IPSW and Albert server implementation.

## Activation Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         iOS DEVICE ACTIVATION FLOW                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. DEVICE BOOT (Recovery/DFU/Hello Screen)                                │
│     │                                                                       │
│     ▼                                                                       │
│  2. DRM HANDSHAKE (/deviceservices/drmHandshake)                           │
│     │  • Device sends HandshakeRequestMessage + optional CSR               │
│     │  • Albert returns ServerCertificate (FairPlay chain), ServerRandom,  │
│     │    SessionID, ServerSignature                                        │
│     │  • Establishes encrypted session                                     │
│     ▼                                                                       │
│  3. DEVICE ACTIVATION (/deviceservices/deviceActivation)                   │
│     │  • Device sends activation-info (base64 plist) with:                │
│     │    - IMEI (15 digits) / InternationalMobileEquipmentIdentity        │
│     │    - IMSI / InternationalMobileSubscriberIdentity                   │
│     │    - ICCID / IntegratedCircuitCardIdentity                          │
│     │    - UDID / UniqueDeviceID                                           │
│     │    - SerialNumber                                                    │
│     │    - ProductType (e.g., iPhone11,8)                                  │
│     │    - ActivationRandomness (nonce)                                    │
│     │    - DeviceCertRequest (CSR for device cert)                        │
│     │                                                                      │
│     │  • Albert validates IMEI (15 digits), UDID (40 hex), Serial         │
│     │  • Generates AccountToken with IMEI/IMSI/ICCID embedded             │
│     │  • Signs AccountToken with FairPlay key (SHA1, Apple ARS spec)      │
│     │  • Generates/returns DeviceCertificate from CSR                     │
│     │  • Returns activation-record plist with:                            │
│     │    - AccountToken (base64 plist)                                     │
│     │    - AccountTokenCertificate                                         │
│     │    - AccountTokenSignature (FairPlay SHA1)                          │
│     │    - DeviceCertificate                                               │
│     │    - FairPlayKeyData (placeholder)                                   │
│     │    - WildcardTicket                                                  │
│     │    - RegulatoryInfo                                                  │
│     ▼                                                                       │
│  4. POST-ACTIVATION SYNC                                                   │
│     │  • Device contacts ActivityURL: https://albert.apple.com/           │
│     │    deviceservices/activity                                           │
│     │  • CertificateURL: https://albert.apple.com/                        │
│     │    deviceservices/certifyMe                                          │
│     │  • PhoneHomeURL: https://albert.apple.com/                          │
│     │    WebObjects/ALUnbrick.woa/wa/phoneHome                            │
│     ▼                                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## IMEI in Activation Process

### 1. IMEI Validation (albert_server.py:1304-1323)

```python
_IMEI_RE = re.compile(r"^\d{15}$")  # Exactly 15 digits

def validate_imei(imei: str) -> bool:
    return bool(_IMEI_RE.fullmatch(str(imei).strip()))
```

**Validation Rules:**
- Must be exactly 15 digits (Luhn algorithm not enforced by Albert, but Apple devices enforce it)
- Rejected with 400 if invalid
- Accepted keys: `IMEI` or `InternationalMobileEquipmentIdentity`

### 2. AccountToken Generation (albert_server.py:1070-1095)

```python
account_token = {
    "InternationalMobileEquipmentIdentity": activation_info.get("IMEI", 
        activation_info.get("InternationalMobileEquipmentIdentity", "")),
    "InternationalMobileSubscriberIdentity": activation_info.get("IMSI",
        activation_info.get("InternationalMobileSubscriberIdentity", "")),
    "IntegratedCircuitCardIdentity": activation_info.get("ICCID",
        activation_info.get("IntegratedCircuitCardIdentity", "")),
    "ActivationRandomness": activation_info.get("ActivationRandomness", 
        str(uuid.uuid4())),
    "UniqueDeviceID": activation_info.get("UniqueDeviceID", str(uuid.uuid4())),
    "ActivityURL": "https://albert.apple.com/deviceservices/activity",
    "CertificateURL": "https://albert.apple.com/deviceservices/certifyMe",
    "PhoneNumberNotificationURL": "https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/phoneHome",
    "WildcardTicket": base64.b64encode(b"wildcard_ticket_placeholder").decode()
}
```

**Key Fields:**
| Field | Source | Purpose |
|-------|--------|---------|
| `InternationalMobileEquipmentIdentity` | Device IMEI (15 digits) | Primary device identifier for cellular network |
| `InternationalMobileSubscriberIdentity` | SIM IMSI | Subscriber identity on carrier network |
| `IntegratedCircuitCardIdentity` | SIM ICCID | SIM card unique identifier |
| `UniqueDeviceID` | Device UDID | Apple device unique identifier |
| `ActivationRandomness` | Device nonce | Replay attack prevention |

### 3. AccountToken Signing (FairPlay SHA1)

```python
def sign_activation_info(self, activation_info: bytes) -> bytes:
    # SHA1 required by Apple's activation spec for FairPlay signature
    # (ARS = base64(SHA1(response_plist)))
    signature = self.fairplay_private_key.sign(
        activation_info, 
        padding.PKCS1v15(), 
        hashes.SHA1()  # Apple-spec, not for general hashing
    )
    return signature
```

**Signature Process:**
1. AccountToken dict → plist binary → base64
2. Signed with FairPlay private key (RSA-2048, PKCS1v15, SHA1)
3. Signature embedded in `AccountTokenSignature` field
4. Returned as base64 in activation record

## IMEI in Baseband Firmware

### Baseband Components (from BuildManifest)

```
BasebandFirmware: Firmware/ICE18-7.03.02.Release.bbfw (37 MB)
  Sub-components (via download digests):
  - 2GFW, 3GFW, AudioFW, BBCFG, CDMA2KFW, Custpack
  - DPC, DebugFW, EBL, LTEFW, RFFW, RPCU
  - SystemSW, TDSFW
  - PSI-Version + PSI-PartialDigest (partial signing info)
```

### Baseband Responsibilities

| Component | Function | IMEI Role |
|-----------|----------|-----------|
| **LTEFW** | LTE modem firmware | Stores/validates IMEI in NV memory |
| **BBCFG** | Baseband configuration | IMEI binding to device |
| **SystemSW** | Baseband OS | IMEI attestation to AP |
| **PSI** | Partial Signing Info | IMEI in certificate chain |

### IMEI Storage in Baseband

The baseband stores IMEI in **Non-Volatile (NV) memory** during manufacturing:
- **OTP (One-Time Programmable)** fuses for IMEI
- **NV RAM** for IMEI + certificates
- **Secure Enclave** (SEP) holds device UID/GID bound to IMEI

## Sync Activated Feature

### What "Sync Activated" Means

After successful activation, the device enters **"sync activated"** state where:

1. **Device is registered** in Apple's activation database (Albert)
2. **Push token registered** for APNs (Apple Push Notification service)
3. **iCloud sync enabled** - device can sync contacts, calendars, etc.
4. **Find My iPhone enabled** - device trackable via iCloud
5. **Carrier activation complete** - IMEI registered with carrier

### Sync Endpoints (from AccountToken)

```python
"ActivityURL": "https://albert.apple.com/deviceservices/activity",
"CertificateURL": "https://albert.apple.com/deviceservices/certifyMe",
"PhoneNumberNotificationURL": "https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/phoneHome",
```

| Endpoint | Purpose | IMEI Usage |
|----------|---------|------------|
| `/activity` | Device activity reporting | Reports IMEI status to Apple |
| `/certifyMe` | Certificate renewal | Re-validates IMEI-bound certs |
| `/phoneHome` | Phone number notification | Links IMEI to phone number |

### Sync Flow

```
Device (activated)                           Albert Server
     │                                           │
     ├─ POST /deviceservices/activity ─────────►│
     │  { IMEI, UDID, status, push_token }      │
     │                                           │
     ◄─ 200 OK (sync confirmed) ────────────────┤
     │                                           │
     ├─ POST /deviceservices/certifyMe ────────►│
     │  { CSR for new cert }                    │
     │                                           │
     ◄─ New DeviceCertificate ──────────────────┤
     │                                           │
```

## Reverse Engineering: IMEI in Firmware Components

### 1. DeviceTree (n841ap)

The DeviceTree contains hardware identity:
```bash
# Extracted from Firmware/all_flash/DeviceTree.n841ap.im4p
# Contains: /chosen/boot-manifest-hash, /chosen/unique-id (UID), etc.
```

### 2. SEP Firmware (sep-firmware.n841.RELEASE.im4p)

Secure Enclave Processor firmware handles:
- **UID/GID** - Hardware keys bound to device (and indirectly IMEI)
- **Keybag** - Encryption keys for file system
- **Activation tickets** - SEP-signed activation records

### 3. KernelCache

iOS kernel handles:
- **IOKit device matching** - IMEI via `IOPlatformExpert`
- **MobileActivation framework** - `MobileActivation-592.103.2`
- **FairPlay kernel extension** - `AppleFairPlayKernel`

### 4. Activation-Related Frameworks (in OS DMG)

The OS volume (`094-31934-038.dmg.aea`) contains:
```
/System/Library/PrivateFrameworks/MobileActivation.framework
/System/Library/PrivateFrameworks/FairPlay.framework
/System/Library/PrivateFrameworks/IDS.framework (Identity Services)
/System/Library/PrivateFrameworks/Baseband.framework
```

## IMEI-Based Sync Activation Implementation

### Local Albert Implementation

To implement "sync activated" feature locally:

```python
# 1. Extend activation record with sync tokens
def create_sync_activation_record(self, activation_info: dict) -> dict:
    base_record = self.create_activation_record(activation_info)
    
    # Add sync-specific fields
    sync_data = {
        "PushToken": activation_info.get("PushToken", ""),
        "APNsTopic": f"com.apple.activation.{activation_info['IMEI']}",
        "SyncEnabled": True,
        "FindMyiPhoneEnabled": True,
        "iCloudSyncEnabled": True,
        "CarrierActivated": True,
        "ActivationTimestamp": datetime.now(timezone.utc).isoformat()
    }
    
    base_record["activation-record"]["SyncData"] = base64.b64encode(
        plistlib.dumps(sync_data)
    ).decode()
    
    return base_record

# 2. Implement activity endpoint
@app.route('/deviceservices/activity', methods=['POST'])
def activity():
    data = plistlib.loads(request.get_data())
    imei = data.get("IMEI") or data.get("InternationalMobileEquipmentIdentity")
    udid = data.get("UDID") or data.get("UniqueDeviceID")
    
    # Log sync activity
    log_sync_activity(imei, udid, data)
    
    return {"Status": "Acknowledged", "SyncInterval": 3600}

# 3. Implement certifyMe endpoint
@app.route('/deviceservices/certifyMe', methods=['POST'])
def certify_me():
    csr = request.get_data()
    # Generate new device cert bound to IMEI/UDID
    cert = generate_device_certificate(csr)
    return cert
```

### Sync State Persistence

```sql
-- In activations.db
CREATE TABLE sync_state (
    udid TEXT PRIMARY KEY,
    imei TEXT NOT NULL,
    push_token TEXT,
    apns_topic TEXT,
    sync_enabled BOOLEAN DEFAULT 1,
    find_my_enabled BOOLEAN DEFAULT 1,
    icloud_enabled BOOLEAN DEFAULT 1,
    carrier_activated BOOLEAN DEFAULT 1,
    last_sync TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## IMEI Validation & Carrier Check

### Luhn Algorithm (IMEI Check Digit)

```python
def validate_imei_luhn(imei: str) -> bool:
    """Validate IMEI using Luhn algorithm (last digit is check digit)."""
    if not re.match(r"^\d{15}$", imei):
        return False
    digits = [int(d) for d in imei]
    check_digit = digits[-1]
    total = 0
    for i, d in enumerate(digits[:-1]):
        if i % 2 == 0:
            total += d
        else:
            doubled = d * 2
            total += doubled if doubled < 10 else doubled - 9
    return (total * 9) % 10 == check_digit
```

### Carrier Activation Check (TAC)

```python
# Type Allocation Code (first 8 digits) identifies manufacturer/model
TAC_DATABASE = {
    "35000000": "Apple iPhone XR (A12)",
    "35678901": "Apple iPhone 12 (A14)",
    # ... more TACs
}

def get_device_from_tac(imei: str) -> str:
    tac = imei[:8]
    return TAC_DATABASE.get(tac, "Unknown")
```

## Security Considerations

### IMEI Spoofing Prevention

1. **Baseband enforces IMEI** - Hardware OTP fuses prevent change
2. **SEP attests IMEI** - Secure Enclave signs activation with UID bound to IMEI
3. **Albert validates format** - 15 digits, but not Luhn (Apple does)
4. **Carrier network validates** - IMEI checked against GSMA database

### Activation Record Security

| Protection | Implementation |
|------------|----------------|
| **Integrity** | FairPlay SHA1 signature (Apple ARS spec) |
| **Replay prevention** | ActivationRandomness (nonce) |
| **Device binding** | DeviceCertificate from CSR + UDID |
| **Confidentiality** | TLS (mitmproxy terminates) |

## Testing IMEI Activation

`activate_device.py` has no `--imei` flag — the client arguments are `--udid`,
`--albert-url`, `--skip-apple-id`, `--method`, `--info`, `--json`, `--timeout`,
`--retries`. There is no Luhn pre-validation on the client either; IMEI handling
lives server-side. Test the server path directly instead:

```bash
# Activate a device (IMEI is read from the paired device, not from argv)
python3 activate_device.py --method direct --udid 00008020-AAAAAAAAAAAAAAAA --json

# Check sync state
curl -H "X-Admin-Token: $ALBERT_ADMIN_TOKEN" \
  http://127.0.0.1:18090/api/activations?limit=5
```

## References

- [Apple MobileActivation Protocol](https://theapplewiki.com/wiki/Albert)
- [FairPlay DRM](https://theapplewiki.com/wiki/FairPlay)
- [IMEI Structure (GSMA)](https://www.gsma.com/imei/)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- BuildManifest.plist analysis (this repo: `docs/IPSW_REVERSE_ENGINEERING.md`)

## Files for Reference

```
/home/cvsz/albert_server/
├── albert_server.py              # Main activation server
├── firmware_server.py            # Local firmware/TSS server
├── firmware_restore_proxy.py     # mitmproxy redirect rules
├── activate_device.py            # Activation client
├── firmware/BuildManifest.plist  # Component manifest
├── firmware/Firmware/ICE18-7.03.02.Release.bbfw  # Baseband
└── docs/
    ├── IPSW_REVERSE_ENGINEERING.md
    └── IMEI_ACTIVATION_REVERSE_ENGINEERING.md  # This file
```