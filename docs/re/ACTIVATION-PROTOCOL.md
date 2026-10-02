# โปรโตคอล iOS Activation — บันทึกการวิเคราะห์ย้อนกลับ

เก็บข้อมูลเมื่อ 2026-09-30 โดยวิเคราะห์กับ iPhone11,8 (iPhone XR) ตัวจริงบน iOS 18.7.10 (22H374)
ECID `0x…78002e` โดยใช้ session material ของตัวเครื่องที่เชื่อมต่ออยู่

สคริปต์ที่ใช้: `scripts/capture_activation_trace.py`, `scripts/decode_handshake_artifacts.py`,
`scripts/decode_handshake_framing.py`, `scripts/compare_handshake_shapes.py`
ผลลัพธ์ดิบ: `activation_trace.json`, `handshake_decode.json`, `handshake_framing.json`

## สรุป

ขั้นตอน activation แบบ session-based มี 4 hop ระหว่างเครื่อง host กับ Apple
Hop ที่ 1–3 เป็นแบบ **ไม่สมมาตร**: ตัวเครื่องสร้างข้อมูล Apple ตรวจสอบและลงนามกลับ
ส่วน hop ที่ 4 เป็นของ Apple ล้วน

จุดเชื่อความน่าเชื่อถือ (trust anchor) คือคีย์ RSA ขนาด 1024 bit
ซึ่ง **แยกออกมาจากสายส่งข้อมูลไม่ได้** — ส่งมาแค่ *certificate* เท่านั้น
การปลอมแปลง handshake จึงต้องใช้ private key ที่ไม่เคยออกจาก Apple
นี่คือเหตุผลที่ local server ไม่สามารถมาแทน `albert.apple.com` ได้
ไม่ว่าจะ implement ดีแค่ไหนก็ตาม

## Hop 1 — ตัวเครื่อง → host: session challenge

ส่ง `CreateTunnel1SessionInfoRequest` ไปที่ `com.apple.mobileactivationd`:

| Key | Bytes | ความหมาย |
|---|---|---|
| `CollectionBlob` | 27438 | payload การรับรองข้อมูลตัวเครื่องขนาดใหญ่ |
| `HandshakeRequestMessage` | 21 | nonce / challenge |
| `UniqueDeviceID` | 25 | UDID |

## Hop 2 — host → Apple: `drmHandshake`

Header ของ request เป็นข้บังคับ Apple จะปฏิเสธ request หากไม่มี
User-Agent ที่ตรงทุกตัวอักษรคือ
`iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)`
พร้อมด้วย `Accept: application/xml` และ `Expect: 100-continue`

response เป็น `application/xml` ขนาด 1,672–1,688 bytes มี **4** key:

| Key | Bytes | หมายเหตุ |
|---|---|---|
| `serverKP` | 85 | ASN.1 context tag `0x03`; key blob ไม่ระบุโครงสร้าง |
| `FDRBlob` | 32 | nonce |
| `SUInfo` | 366 | `9502 0100 …` — versioned TLV, v2 / body 256 bytes |
| `HandshakeResponseMessage` | 508 | `0x02` = OCTET STRING; **มีลายเซ็น** |

## Hop 3 — ตัวเครื่องตรวจสอบลายเซ็นของ Apple

`CreateTunnel1ActivationInfoRequest` โดยส่ง handshake response ดิบจาก Apple
ตัวเครื่องตรวจสอบลายเซ็น แล้วส่ง activation info กลับมา:

| Key | Bytes | หมายเหตุ |
|---|---|---|
| `ActivationInfoXML` | 13818 | XML plist มี 8 section (ดูตารางล่าง) |
| `FairPlayCertChain` | 2812 | **certificate DER ต่อกันหลายใบ** ไม่มี outer framing |
| `FairPlaySignature` | 128 | raw signature RSA-1024 |
| `RKCertification` | 975 | รูปร่างคล้าย DER แต่เป็น container ไม่มาตรฐาน |
| `RKSignature` | 71 | ไม่ใช่ RSA-128; น่าจะเป็น ECDSA P-256 `r‖s` + trailer |
| `serverKP` | 85 | ส่งคืนค่าเดิมจาก response ของ Apple |
| `signActRequest` | 16 | `f2c87a7a04f3eee930177232e55c2637` |

จำนวน key ใน `ActivationInfoXML`:

| Section | จำนวน Keys |
|---|---|
| `ActivationRequestInfo` | 3 (`ActivationRandomness`, `ActivationState`, `FMiPAccountExists`) |
| `BasebandRequestInfo` | 11 (IMEI, IMEI2, MEID, BasebandChipID, SIMStatus, …) |
| `DeviceInfo` | 12 |
| `UIKCertification` | 6 |
| `DeviceID` | 2 |
| `DeviceCertRequest` | blob ขนาด 696 bytes |
| `RegulatoryImages` | 1 |
| `SoftwareUpdateRequestInfo` | 1 |

## Hop 4 — host → Apple: `deviceActivation`

ส่งแบบ form-encoded พร้อม `activation-info` (blob จาก hop 3) และ `AppleSerialNumber`
พบรูปแบบ response 2 แบบ:

* `application/xml` — สำเร็จ มี activation record
* `application/x-buddyml` — เป็น form setup แบบ HTML-ish

ผลลัพธ์ `buddyml` ที่พบจริง:

| สถานการณ์ | เนื้อหา |
|---|---|
| เปิด Activation Lock | form ขอ Apple ID + password ของเจ้าของ |
| credentials ถูกปฏิเสธ | `<alert title='Apple Account disabled'>` |
| ยังไม่ได้ sign in | form "Set Up as a New iPhone" แบบ `application/x-buddyml` |

## Trust anchor

certificate ใบแรกใน `FairPlayCertChain`:

```
subject : CN=iPhone.3333AF070402AF0002AF000003,OU=Apple FairPlay,O=Apple Inc.,C=US
issuer  : CN=Apple FairPlay Certification Authority,OU=Apple Certification Authority,O=Apple Inc.,C=US
serial  : 3333af070402af0002af000003
key     : 1024-bit RSA
expires : 2012-03-31
```

RSA-1024, SHA-1, หมดอายุตั้งแต่ปี 2012 — อ่อนแอตามมาตรฐานสมัยใหม่
และนั่นเป็นข้อสังเกตที่ควรบันทึกไว้โดยอิสระ
แต่มันไม่ได้ช่วยคนที่จะปลอมแปลง เพราะสิ่งที่ **จำเป็น** คือ *private* key
ซึ่งไม่เคยปรากฏบนสายส่งข้อมูล มีแต่ certificate เท่านั้นที่ถูกส่งมา

## ทำไม local server จึงแทน Apple ไม่ได้

`drm_handshake` ใน `albert_server.py` คืน 5 key ส่วน Apple คืน 4 key
ทั้งสองชุดทับซ้อนกันแค่ 1 key:

| | Apple จริง | local server |
|---|---|---|
| `serverKP` | 85 B | ไม่มี |
| `FDRBlob` | 32 B | ไม่มี |
| `SUInfo` | 366 B | ไม่มี |
| `HandshakeResponseMessage` | **508 B มีลายเซ็น** | 30 B ข้อความ `handshake_response_placeholder` |
| `ServerRandom` | — | 32 B (ไม่ใช่ field ของ Apple) |
| `SessionID` | — | uuid4 (ไม่ใช่ field ของ Apple) |
| `ServerCertificate` | — | 21 B (ไม่ใช่ field ของ Apple) |
| `ServerSignature` | — | 28 B ข้อความ `server_signature_placeholder` |

3 key ในฝั่ง local **ไม่มีอยู่จริงในโปรโตคอลของ Apple** ส่วน key ที่ทับซ้อนกัน
คือ placeholder ขนาด 30 B ในตำแหน่งที่ Apple ส่งข้อมูลมีลายเซ็น 508 B

การยืนยันเชิงทดลอง: ส่ง `HandshakeResponseMessage` 3 โครงสร้างที่ต่างกัน
(สะท้อนค่า challenge, ค่าว่าง, เต็มด้วยศูนย์) เข้าไปที่ตัวเครื่องโดยตรง
ผลลัพธ์ทั้งสามแบบเหมือนกันทุกประการ คือ `Invalid session response`
ตัวเครื่องปฏิเสธจาก **ความถูกต้องของลายเซ็น** ไม่ใช่จากโครงสร้างหรือความยาว
ไม่มีการจัดเรียง byte ใด ๆ ที่ผ่านได้

placeholder เหล่านี้มีอยู่ตั้งแต่ commit แรก `8930ec5` และไม่เคยเป็น
implementation จริงเลย `docs/PRODUCTION_GAP_ANALYSIS.md` P1-5 บันทึกข้อจำกัดเดียวกันไว้

## ข้อค้นพบรอง: สถานะ Activation Lock มองไม่เห็นจาก local state

lockdownd รายงาน:

```
ActivationState        = Unactivated
ActivationDeviceUserID = MissingValueError
iCloudActivationState  = MissingValueError
IsActivationLocked     = MissingValueError
```

แต่ `deviceActivation` ของ Apple กลับคืน Activation Lock form ที่ผูกกับ
Apple account เฉพาะรายการ **local state query จึงบอกไม่ได้ว่าเครื่องถูกล็อกหรือไม่**
มีแต่ Apple เท่านั้นที่ตอบได้ เครื่องมือใด ๆ ที่อนุมานสถานะ lock จาก lockdownd จึงไม่น่าเชื่อถือ

## ข้อสรุปในทางปฏิบัติ

สำหรับเครื่องที่เจ้าของเป็นผู้ถือ ทางที่รองรับคือใช้ endpoint จริงเท่านั้น
ยืนยันแล้วกับเครื่องตัวนี้: เมื่อ unblock `albert.apple.com` ใน `/etc/hosts`
ตัวเครื่องยอมรับ handshake จาก Apple ในครั้งแรกที่ลอง

local server ยังมีประโยชน์สำหรับงานวิจัยโปรโตคอล การทดสอบ logic ของ
`/deviceActivation` การตรวจ rate limiting และ input validation และ regression test
แต่ไม่สามารถใช้เพื่อ activate เครื่องได้

## Hop 1 เชิงลึก: โครงสร้างจริงของ `CollectionBlob`

เก็บจากเครื่องจริงอีกครั้งเมื่อ 2026-10-02 ผ่าน `pymobiledevice3` 11.19.4
(`MobileActivationService.create_activation_session_info()`) โดยไม่ได้แตะเส้นทาง
FairPlay — เป็นการถอดเฉพาะสิ่งที่ตัวเครื่อง**ส่งออก**เอง

### ชั้นที่ 1 — XML plist 3 key

`CollectionBlob` เป็น XML plist (~27.4 KB) มี 3 key:

| Key | ชนิด | ขนาด |
|---|---|---|
| `IngestBody` | `data` | ~19.6 KB |
| `X-Apple-Sig-Key` | `string` | base64 public key ของ ECDSA-P256 |
| `X-Apple-Signature` | `string` | DER `SEQUENCE` 96 B (`MEUC…` = ECDSA sig) |

ทั้ง signature และ key เปลี่ยนทุก session — เป็น ephemeral key ที่ตัวเครื่องสร้างใหม่
เพื่อเซ็น `IngestBody` ในรอบนั้น ไม่ใช่คีย์ Apple คงที่ ดังนั้นการเซ็นนี้พิสูจน์ได้แค่ว่า
"เนื้อหาไม่ถูกแก้ระหว่างทาง" ไม่ใช่ว่า "มาจาก Apple"

### ชั้นที่ 2 — `IngestBody` เป็น JSON plaintext

ตรงนี้เป็นจุดที่เอกสารเดิมบันทึกผิด — เคยสันนิษฐานว่าเป็น binary/protobuf
จริงๆ คือ **JSON ข้อความล้วน** entropy 6.04 bits/byte (ไม่ใช่ 8.0 แบบข้อมูลเข้ารหัส)
มี 11 field:

| Field | ค่า/ชนิด |
|---|---|
| `serial-number` | SN ของเครื่อง |
| `udid` | UDID |
| `imei`, `ime2`, `meid` | IMEI / IMEI2 / MEID |
| `productType` | `iPhone11,8` |
| `os-version`, `os-build` | `18.7.10`, `22H374` |
| `pcrt` | base64 → 5829 B |
| `scrt-part1` | base64 → ~7.2 KB |
| `scrt-part2` | base64 → ~1.2 KB |

จุดที่ต้องระวัง: ฟิลด์ IMEI/MEID/serial/UDID อยู่ใน plaintext ที่ตัวเครื่องส่งออกมาตั้งแต่
hop 1 ไม่ต้องรอ drmHandshake ดังนั้น log ของ host ที่เก็บ request ดิบคือที่เก็บข้อมูลระบุตัว
ตัวเครื่องไว้เต็ม ๆ และต้อง redact ตามที่ SECURITY.md กำหนด

### ชั้นที่ 3 — `pcrt` / `scrt-*`

ทั้งสามเป็น binary container ของ Apple ไม่ใช่ DER ที่ parse ตรงๆ ได้

- `pcrt` — 5829 B **เหมือนเดิมทุก session** (byte-for-byte) entropy 7.97
  โครงสร้างเปิดด้วย `04 00` แล้วเป็น byte ที่ไม่ใช่ ASN.1 tag → สรุปว่าเป็น
  provisioning record ที่ผูกกับเครื่อง ไม่ใช่ per-session material
- `scrt-part1` / `scrt-part2` — ASN.1 `SEQUENCE { INTEGER 2, SEQUENCE { OCT… } }`
  เปลี่ยนทุก session และ **ขนาดเปลี่ยนด้วย** ภายในมี OCTET STRING 5 ก้อน:
  32 B / 65 B / 16 B / 16 B / ก้อนใหญ่ (~1–7 KB) entropy ก้อนใหญ่ ~7.8–7.98
  ต่างจาก 32 B แรก (entropy ~4.9) ชัดเจน → ก้อนเล็กเป็นค่าคงที่/โครงสร้าง ส่วนก้อนใหญ่ถูก
  ปกปิ้วหรือเข้ารหัส ไม่พบ LZ4/LZFSE/zlib magic → คาดว่าเป็น payload ที่ Apple
  เซ็นและฝัง key material สำหรับ SEP ไม่ใช่ certificate ที่แยกออกมาได้ตรงๆ

`scrt` น่าจะย่อมาจาก **SEP CRT** (Secure Enclave certificate) — สอดคล้องกับข้อสรุป
เดิมใน `FIRMWARE-ANALYSIS-FINDINGS.md` ว่า AEA เป็น encrypted ทั้งไฟล์และต้องใช้ key
จาก Apple

### ขนาดที่วัดจริงเทียบเอกสารเดิม

| รายการ | เอกสารเดิม | วัดจริง 2026-10-02 |
|---|---|---|
| `CollectionBlob` | 27438 B | 27410–27454 B (เปลี่ยนทุก session) |
| `HandshakeRequestMessage` | 21 B | 21 B (ตรงเสมอ) |
| `IngestBody` | ไม่ได้บันทึก | 19592–19641 B |

`CollectionBlob` ไม่คงที่เพราะ JSON ภายในมีค่าที่เปลี่ยนตามรอบ (nonce/salt) ตัวเลข
27438 ในเอกสารควรถือเป็นค่าตัวอย่างจาก session นั้น ไม่ใช่ค่าคงที่ของโปรโตคอล

### ขอบเขตที่ยังทำไม่ได้

- ถอด `scrt-*` ก้อนใหญ่ไม่ได้ — ไม่มี key จาก Apple และไม่มี SEP blob ที่ถอดแล้ว
- `pcrt` ระบุ key อะไรผูกอยู่ยังไม่ทราบ ไม่พบ certificate ที่ parse ได้ฝังอยู่
- ยืนยันไม่ได้ว่า `X-Apple-Sig-Key` เป็นของ Apple จริง — เป็น key ที่ตัวเครื่องแนบมาใน
  ข้อความเดียวกัน ผู้รับต้องได้ key จากช่องทางอื่นที่เชื่อถือได้ถึงจะตรวจได้

### สคริปต์ที่ใช้

`pymobiledevice3` 11.19.4 ผ่าน `venv/bin/python` โค้ดวิเคราะห์อยู่ที่
`scripts/inspect_collection_blob.py` (ดูหัวข้อถัดไป)
