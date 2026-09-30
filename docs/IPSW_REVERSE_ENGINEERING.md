# IPSW Reverse Engineering — iPhone11,8 18.7.10 (22H374)

## IPSW Structure Overview

The IPSW is a ZIP archive containing:
- **BuildManifest.plist** — Master manifest with all component digests, paths, and restore rules
- **Restore.plist** — Device compatibility matrix
- **SystemVersion.plist** / **RestoreVersion.plist** — Version metadata
- **Firmware components** — DMG/IM4P files for each subsystem

## Key Files Extracted

| File | Size | Purpose |
|------|------|---------|
| `BuildManifest.plist` | ~272 KB | Complete component manifest with SHA256 digests |
| `Restore.plist` | 1 KB | Device map, product types, supported boards |
| `RestoreVersion.plist` | 1 KB | Build version strings |
| `SystemVersion.plist` | 1 KB | OS version, build ID |

## BuildManifest.plist Structure

### Root Keys
```xml
<dict>
  <key>BuildIdentities</key>     <!-- Array of 2: Erase + Update variants -->
  <key>ManifestVersion</key>     <!-- "1" -->
  <key>ProductBuildVersion</key> <!-- "22H374" -->
  <key>ProductVersion</key>      <!-- "18.7.10" -->
  <key>SupportedProductTypes</key> <!-- ["iPhone11,8"] -->
</dict>
```

### BuildIdentities (2 variants)
| Index | Variant | RestoreBehavior | Description |
|-------|---------|-----------------|-------------|
| 0 | Customer Erase Install (IPSW) | Erase | Full restore, wipes data |
| 1 | Customer Upgrade Install (IPSW) | Update | OTA-style upgrade, preserves data |

Both share identical `Manifest` components; only `RestoreBehavior` differs.

### Component Manifest (80+ components)

Each component has:
```xml
<key>ComponentName</key>
<dict>
  <key>Digest</key>           <!-- Base64 SHA256 -->
  <key>Info</key>
  <dict>
    <key>Path</key>           <!-- Relative path in IPSW -->
    <key>Personalize</key>    <!-- true/false -->
    <key>RestoreRequestRules</key> <!-- Conditional logic for EPRO/ESEC -->
    <key>IsFTAB</key>         <!-- Flash Transfer Abort? -->
    <key>IsLoadedByiBoot</key>
    <key>IsSecondaryFirmwarePayload</key>
    ...
  </dict>
  <key>Trusted</key>          <!-- true/false -->
</dict>
```

### Critical Components for Update Server

| Component | Path | Type | Notes |
|-----------|------|------|-------|
| **OS** | `094-31934-038.dmg.aea` | APFS DMG (6.5 GB) | Main system volume, encrypted (AEA) |
| **Cryptex1,SystemOS** | `094-32062-038.dmg.aea` | APFS DMG (1.6 GB) | System Cryptex |
| **Cryptex1,AppOS** | `094-32850-038.dmg` | DMG (16 MB) | App Cryptex |
| **RestoreRamDisk** | `094-32147-038.dmg` | DMG (176 MB) | Restore ramdisk |
| **RestoreSEP** | `Firmware/all_flash/sep-firmware.n841.RELEASE.im4p` | IM4P (6 MB) | Secure Enclave |
| **KernelCache** | `kernelcache.release.iphone11b` | KCache (18 MB) | Kernel + kexts |
| **iBoot** | `Firmware/all_flash/iBoot.n841.RELEASE.im4p` | IM4P (1.5 MB) | Bootloader |
| **iBEC/iBSS** | `Firmware/dfu/*.im4p` | IM4P | DFU/Recovery boot |
| **BasebandFirmware** | `Firmware/ICE18-7.03.02.Release.bbfw` | BBFW (37 MB) | Cellular modem |

### Baseband Sub-components (in BasebandFirmware)
The `BasebandFirmware` manifest contains multiple download digests:
- `2GFW`, `3GFW`, `AudioFW`, `BBCFG`, `CDMA2KFW`, `Custpack`, `DPC`, `DebugFW`, `EBL`, `LTEFW`, `RFFW`, `RPCU`, `SystemSW`, `TDSFW`
- Each has `DownloadDigest` + `HashTableDigest`
- `PSI-Version` + `PSI-PartialDigest` for partial signing info

## Device Identity (from Restore.plist)

```xml
<dict>
  <key>BDID</key>           <integer>12</integer>
  <key>BoardConfig</key>    <string>n841ap</string>
  <key>CPID</key>           <integer>32800</integer>  <!-- A12 = 0x8020 -->
  <key>Platform</key>       <string>t8020</string>
  <key>SCEP</key>           <integer>0</integer>
  <key>SDOM</key>           <integer>1</integer>
</dict>
```

- **CPID 32800** = A12 Bionic (0x8020)
- **BoardConfig n841ap** = iPhone XR (iPhone11,8)
- **Platform t8020** = A12 SoC family

## Update Server Endpoints (Apple)

### TSS (Tatsu Signing Server) — `gs.apple.com`
```
GET /TSS/controller?action=2
  &deviceid=<ECID>
  &buildid=<BuildID>
  &boardid=<BoardID>
  &chipid=<CPID>
  &apsecuritydomain=<domain>
  &approductionmode=<0|1>
  &aprawsecuritymode=<0|1>
  &uniquebuildid=<UniqueBuildID>
  &nonce=<nonce>
```
Returns signed `SHSH` blob (plist) with APTicket.

### Firmware Download — `mesu.apple.com` / `appldnld.apple.com`
```
GET /<path>/<component>.dmg
```
Serves raw DMG/IM4P files. Requires valid cookies/tokens from TSS.

### Update Check — `mesu.apple.com`
```
GET /version/check
```
Returns available updates for device.

## Local Update Server Design

### Required Capabilities

1. **Serve BuildManifest.plist** — Device requests this to know what to download
2. **Serve Component Files** — DMG/IM4P files by path
3. **TSS Endpoint** — Sign SHSH blobs for components (APTicket)
4. **Personalization** — Generate per-device personalized components (APTicket, SEP, etc.)

### Minimal Implementation

```
Local Update Server
├── /BuildManifest.plist          ← Static (from IPSW)
├── /Restore.plist                ← Static
├── /components/<path>            ← File server for DMG/IM4P
├── /TSS/controller               ← Sign SHSH (requires FairPlay keys)
└── /personalize/<component>      ← Generate personalized IM4P
```

### Component Serving Strategy

| Component | Size | Serve Method |
|-----------|------|--------------|
| OS (6.5 GB) | Large | Range requests, streaming |
| Baseband (37 MB) | Medium | Direct |
| KernelCache (18 MB) | Medium | Direct |
| SEP/SE/iBoot | Small | Direct |
| TrustCaches | Tiny | Direct |

### Personalization Required

Components with `Personalize: true` need per-device signing:
- OS, SystemVolume, Cryptex volumes → APTicket with device ECID
- SEP, RestoreSEP → SEP ticket with device UID
- RestoreRamDisk, RestoreTrustCache → Device-specific
- iBoot, iBEC, iBSS → Production-signed (can use stock)

### APTicket Structure (from TSS response)
```xml
<dict>
  <key>ApTicket</key>
  <dict>
    <key>ApECID</key>           <integer>...</integer>
    <key>ApNonce</key>          <data>...</data>
    <key>ApProductionMode</key> <true/>
    <key>ApSecurityDomain</key> <integer>1</integer>
    <key>ApTicket</key>         <data>...</data>  <!-- CMS signed -->
  </dict>
</dict>
```

## Implementation Notes for albert_server

### Current State
- Albert handles **activation** (`albert.apple.com`)
- TSS (`gs.apple.com`) passes through to Apple
- No local firmware serving or SHSH signing

### To Add Local Update Server

1. **Extract IPSW components** to local storage (`/firmware/iPhone11,8_18.7.10/`)
2. **Add firmware HTTP server** (nginx or Python) on port 18091
3. **Implement TSS endpoint** in `albert_server.py`:
   - Parse TSS request parameters
   - Generate APTicket with local FairPlay key
   - Return signed CMS payload
4. **Add BuildManifest serving** at `/BuildManifest.plist`
5. **Integrate with mitmproxy** to intercept `mesu.apple.com` / `appldnld.apple.com`

### mitmproxy Rules for Update Server
```python
# In firmware_restore_proxy.py
UPDATE_HOSTS = [
    "mesu.apple.com",
    "appldnld.apple.com", 
    "gs.apple.com",      # TSS - can intercept for local signing
]
```

### Security Considerations
- **SHSH signing** requires Apple's root CA or custom CA trusted by device
- **Personalization** needs device ECID, UID, GID (from activation)
- **AEA encryption** on OS/Cryptex DMGs — need KBAG decryption keys
- **TrustCache** must match device's trust cache policy

## Files for Reference

```
/home/cvsz/albert_server/extracted_ipsw/
├── BuildManifest.plist          # Full manifest
├── Restore.plist                # Device compatibility
├── RestoreVersion.plist         # Build version
├── SystemVersion.plist          # OS version
└── (extracted components on demand)
```

## Next Steps

1. Extract key components on-demand (not full 8 GB)
2. Implement TSS endpoint with CMS signing
3. Add firmware HTTP file server
4. Configure mitmproxy to redirect update hosts
5. Test with `idevicerestore` or `futurerestore` pointing to local server