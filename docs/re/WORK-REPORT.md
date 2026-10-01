# รายงานงาน — Restore, Activation และการวิจัย Firmware ของ iPhone XR

อุปกรณ์: iPhone XR (`iPhone11,8` / `n841ap`, A12 Bionic), BoardID `0x0C`, ChipID `0x8020`
Serial: `…EKXKQ`  UDID: `00008020-…2E`  ECID: `0x…78002e`
โฮสต์: VMware guest `albert-core` (Ubuntu 26.04), repo `/home/cvsz/albert_server`
ช่วงเวลา: 2026-09-30

### เอกสารอ้างอิงภายนอก

`zalive` มี ZEAZ layer อยู่แล้ว (`docs/ai/`, `components.d/`, `skills/zeaz-skill-finder`)
แต่ **specialist RE skills ไม่ได้ถูกนำเข้ามา** — `skills/` ในโปรเจกต์นี้มีแค่ตัว
ค้นหา ส่วน `zeaz-re-apple` / `zeaz-re-firmware` / `zeaz-re-triage` อยู่ที่ `cvsz/zrepro`
(แยก repo, 17 skills)

จึงอ้างอิงข้าม repo แทนการ vendor เข้ามา เพราะ `zalive` เป็น product ไม่ใช่ template
และ `AGENTS.md` กำหนดให้รักษา template portability — specialist layer ที่ต้อง
maintain แยกอยู่ที่เดียวก็พอ

ที่เกี่ยวกับงานในรายงานนี้:

- [`docs/ai/playbooks/apple-reverse-engineering.md`](https://github.com/cvsz/zrepro/blob/main/docs/ai/playbooks/apple-reverse-engineering.md)
- [`docs/ai/playbooks/firmware-reverse-engineering.md`](https://github.com/cvsz/zrepro/blob/main/docs/ai/playbooks/firmware-reverse-engineering.md)
- [`skills/zeaz-re-triage/SKILL.md`](https://github.com/cvsz/zrepro/blob/main/skills/zeaz-re-triage/SKILL.md) — จุดเริ่มต้นตามลำดับ
- [`skills/zeaz-re-apple/SKILL.md`](https://github.com/cvsz/zrepro/blob/main/skills/zeaz-re-apple/SKILL.md)
- [`skills/zeaz-re-firmware/SKILL.md`](https://github.com/cvsz/zrepro/blob/main/skills/zeaz-re-firmware/SKILL.md)

ระบบ evidence-state ของ ZEAZ (`VERIFIED` / `PARTIALLY VERIFIED` / `UNVERIFIED` /
`BLOCKED` / `NOT APPLICABLE`) ใช้ในรายงานนี้แล้ว

---

## 1. สรุปผล

| วัตถุประสงค์ | ผลลัพธ์ |
|---|---|
| Restore iOS 18.7.10 (22H374) | **สำเร็จ** — `Status: Restore Finished` |
| วินิจฉัยการ restore ล้มเหลวราว 12 ครั้ง | **สำเร็จ** — USB passthrough ของ VMware ไม่เสถียร |
| Activate เครื่อง | **ติดขัดที่ Apple** — บัญชีถูก disable; ไม่มีทางแก้ในเครื่อง |
| วิเคราะห์โปรโตคอล activation ย้อนกลับ | **สำเร็จ** — แผนที่ 4 hop และ trust anchor |
| วิเคราะห์โครงสร้าง IPSW 18.7.10 | **สำเร็จ** — 76 components, รูปแบบ Image4/DER, อธิบาย 2 build identities |
| แยก kernel + วิเคราะห์ static | **สำเร็จ** — Mach-O ARM64e 54 MiB, sweep 10.1M instructions, นับ kext 224 ตัว |

มี 2 สมมติฐานที่ผมเสนอช่วงต้น **ผิด** และบันทึกไว้ด้านล่าง:
ทฤษฎีการแย่ง USB ของ `ipheth`/`cdc_ncm` และทฤษฎีว่า `usbmuxd` เป็น daemon ที่
ทำงานผิดปกติ ทั้งสองเป็นปัญหาจริงที่ควรแก้ แต่ไม่ใช่สาเหตุของการ restore ที่ล้มเหลว

มีข้ออ้างหนึ่งข้อจากรายงานระหว่างกางที่ **ผิดและถูกถอนแล้ว**:
การถอดโครงสร้าง entry ของ trustcache เป็นการเดาให้เข้ากับข้อมูล ไม่ใช่การ parse จริง
ดูหัวข้อ §6.2

---

## 2. ขั้นตอน Restore

### 2.1 อาการที่พบ

ทุกความพยายามส่ง recovery component ทั้ง 14 รายการจนได้ 100% แล้วล้มเหลว:

```
Sending RestoreKernelCache (18696803 bytes)...
Uploading [====...====] 100.0%
Waiting for device to enter restore mode...
Device failed to enter restore mode.
Device reconnected in Recovery mode, most likely image personalization failed.
```

`05ac:1280` (Restore Mode) ไม่เคยปรากฏเลยในราว 12 ความพยายาม

### 2.2 สิ่งที่ตัดออกได้

| การตรวจ | ผล |
|---|---|
| SHA-256 ของ IPSW | `b30474b6…a03a46bc4` — สมบูรณ์ |
| สถานะ signing ของ Apple (ipsw.me) | `18.7.10` / `22H374` `signed=True` |
| การดึง TSS/SHSH | สำเร็จ; `shsh/…927982-iPhone11,8-18.7.10.shsh` เป็น Image4 ticket ที่ถูกต้อง |
| `libtatsu` / `idevicerestore` | 1.0.5 / 1.0.1 — เป็นเวอร์ชันล่าสุด |
| BuildManifest / ramdisk variant | ถูกต้อง; 2 identity คือ erase กับ update (ดู §5.2) |
| ดิสก์ / RAM | เหลือ 22 GB, ใช้ได้ 14 GB |
| ความครบถ้วนของการส่งข้อมูล | progress bar ถึง 100% ทั้ง 17 ครั้ง; ไม่มีอะไรค้าง |

### 2.3 สาเหตุที่แท้จริง

USB passthrough ของ VMware ตัวเครื่อง re-enumerate ระหว่าง `usb 1-1` กับ
`usb 1-2` ในทุกรอบ reboot และการเปลี่ยนสถานะ Recovery→Restore
ต้องการการเชื่อมต่อ USB ที่ไปรอดการเปลี่ยนแปลงนั้น
การรันของผู้ใช้เอง **บนเครื่อง physical host** สำเร็จทันที

ยืนยันจาก dmesg: `1281` และ `12a8` ปรากฏต่อเนื่องมาก ส่วน `1280` ไม่เคย

### 2.4 การแก้ไขความเข้าใจที่คลาดเคลื่อนระหว่างทาง

* **"ค้างที่ Sending RestoreKernelCache"** — ไม่ใช่การค้าง มันทำงานเสร็จถึง
  100% แล้วเครื่องมือจึงไปขั้นถัดไป สิ่งที่ดูเหมือนค้างเกิดจาก
  filter `grep -v "Uploading"` ของผมเองที่ซ่อน progress bar
* **ทฤษฎี `ipheth`/`cdc_ncm`** — ผิด การ blacklist มีผลแค่ลด noise ใน log
  แต่ไม่เปลี่ยนพฤติกรรม ผม **ลบ blacklist** และโหลด driver กลับเป็นค่า stock
* **daemon `usbmuxd` ผิดปกติ** — เป็นสิ่งที่พบจริง แต่ไม่ใช่สาเหตุ
  daemon เดิมใช้ CPU 57 นาที กับ memory สูงสุด 3.1 GB ในช่วง 27 ชั่วโมง
  และต้องใช้ SIGKILL ถึงจะหยุดได้ รีสตาร์ตแล้วสะอาด แต่ restore ยังล้มเหลว

---

## 3. ขั้นตอน Activation

### 3.1 สายโซ่สาเหตุ (ตัวบล็อก 3 ระดับที่เป็นอิสระจากกัน)

**ตัวบล็อก 1 — mTLS gate ของ local server**
Albert บังคับใช้ client cert/token บน `/deviceservices/*` (`albert_server.py:1016`)
ถ้าไม่มี จะคืน JSON status 401 ให้ client ที่คาดหวัง plist
อาการฝั่งตัวเครื่องคือ:

```
NSCocoaErrorDomain Code=3840 "Unexpected character { at line 1"
Expected ';' or '=' after key at line 1
```

แก้โดย export `ALBERT_MTLS_TOKEN` (client อ่านจาก environment ที่
`activate_device.py:520-529`) ตรวจสอบแล้ว: `401` → `400 Invalid plist`
หมายความว่า request ไปถึง handler แล้ว

**ตัวบล็อก 2 — placeholder DRM handshake**
`drm_handshake` ใน `albert_server.py` คืนค่า placeholder ล้วน ๆ
(มีตั้งแต่ commit แรก `8930ec5`):

```python
"HandshakeResponseMessage": b"handshake_response_placeholder"
"ServerSignature":          b"server_signature_placeholder"
```

ตัวเครื่องปฏิเสธ: `Invalid session response` ที่
`CreateTunnel1ActivationInfoRequest` ก่อนที่ `deviceActivation` จะถูกเรียกเลย

หลักฐานเชิงทดลองว่าเป็นเรื่อง cryptographic ไม่ใช่เรื่องโครงสร้าง:
ส่ง response 3 โครงสร้างที่ต่างกัน (สะท้อน challenge, ค่าว่าง, เต็มด้วยศูนย์)
เข้าไปที่ตัวเครื่องโดยตรง **ทั้งสามแบบล้มเหลวเหมือนกันทุกประการ**

**ตัวบล็อก 3 — `/etc/hosts` redirect**
เครื่อง host นี้ติดต่อ Apple จริงไม่ได้:

```
5:127.0.0.1  albert.apple.com
6:127.0.0.1  osrecovery.apple.com
7:127.0.0.1  appldnld.apple.com
8:127.0.0.1  mesu.apple.com
```

(`gs.apple.com` ถูกตั้งใจยกเว้นไว้ นั่นคือเหตุผลที่ TSS/restore ยังใช้ได้)

### 3.2 จุดพลิก

เมื่อ unblock รายการเหล่านั้น Apple จริงทำ handshake และตัวเครื่องยอมรับ
ในครั้งแรกที่ลอง:

```
handshake response: 1692 bytes from Apple
device accepted Apple handshake
activation info keys: ActivationInfoXML, FairPlayCertChain, FairPlaySignature,
                       RKCertification, RKSignature, serverKP, signActRequest
```

### 3.3 ตัวบล็อกสุดท้าย — Activation Lock แล้วบัญชีถูก disable

lockdownd รายงานว่าไม่มี lock:

```
ActivationState        = Unactivated
ActivationDeviceUserID = MissingValueError
iCloudActivationState  = MissingValueError
```

แต่ Apple คืน Activation Lock form และหลังส่ง credentials ของเจ้าของบัญชีแล้ว:

```
<alert title='Apple Account disabled'>
<alert message='Your account has been disabled for security reasons.
               To enable your account, reset your password at account.apple.com.'>
```

**การ activation ติดขัดที่สถานะบัญชีฝั่ง Apple** ลองใหม่ 2 ครั้ง
response เหมือนเดิมทุก byte (335 bytes) และไม่ลองซ้ำอีก
เพื่อไม่ให้ lockout ยาวนานขึ้น

### 3.4 ทำไม local server จึงแทน Apple ไม่ได้

`drmHandshake` ของ Apple จริงคืน **4 key** ส่วน local server คืน **5 key**
ทับซ้อนกันแค่ 1 key:

| Key | Apple จริง | local server |
|---|---|---|
| `serverKP` | 85 B | ไม่มี |
| `FDRBlob` | 32 B | ไม่มี |
| `SUInfo` | 366 B | ไม่มี |
| `HandshakeResponseMessage` | **508 B มีลายเซ็น** | 30 B placeholder |
| `ServerRandom` | — | 32 B (ไม่ใช่ field ของ Apple) |
| `SessionID` | — | uuid4 (ไม่ใช่ field ของ Apple) |
| `ServerCertificate` | — | 21 B (ไม่ใช่ field ของ Apple) |
| `ServerSignature` | — | 28 B placeholder |

trust anchor ที่แยกออกมาจาก response ของ Apple:

```
subject : CN=iPhone.3333AF070402AF0002AF000003,OU=Apple FairPlay,O=Apple Inc.,C=US
issuer  : CN=Apple FairPlay Certification Authority,OU=Apple Certification Authority
key     : 1024-bit RSA, SHA-1
expires : 2012-03-31
```

RSA-1024/SHA-1 หมดอายุนานมาแล้ว อ่อนตามหน้าตา แต่ไม่เกี่ยวกับการปลอมแปลง
เพราะ **private** key ไม่เคยปรากฏบนสายส่งข้อมูล

### 3.5 คำขอที่ปฏิเสธ

คำขอให้สร้าง custom IPSW เพื่อ activation ถูกปฏิเสธ
นั่นคือการหลบเลี่ยง activation lock และ FairPlay ของ Apple
และเป็นไปไม่ได้ทางเทคนิคด้วย: เทคนิค custom-activation-IPSW ทุกแบบต้องพึ่ง
bootrom exploit และ **A12 ไม่มี** (checkm8 ครอบคลุมแค่ A7–A11)

---

## 4. การวิเคราะห์โปรโตคอล Activation ย้อนกลับ

รายละเอียด: `docs/re/ACTIVATION-PROTOCOL.md` (พร้อม JSON capture 3 ไฟล์)

4 hop:

1. **Session challenge** — ตัวเครื่องคืน `CollectionBlob` (27,438 B),
   `HandshakeRequestMessage` (21 B), `UniqueDeviceID` (25 B)
2. **`drmHandshake`** — ต้องมี User-Agent ตรงทุกตัวอักษรคือ
   `iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)`
   พร้อม `Accept: application/xml` และ `Expect: 100-continue`
   ไม่มี Apple จะคืน `application/json` ยาว 0 ไม่มี 4 key
3. **ตัวเครื่องตรวจสอบ Apple** — `CreateTunnel1ActivationInfoRequest`
   คืน `ActivationInfoXML` (XML plist 13,818 B, 8 section), `FairPlayCertChain`
   (2,812 B), `FairPlaySignature` (128 B), `RKCertification` (975 B),
   `RKSignature` (71 B), `serverKP`, `signActRequest` (16 B)
4. **`deviceActivation`** — `text/xml` เมื่อสำเร็จ, `application/x-buddyml`
   form เมื่อไม่สำเร็จ พบรูปแบบล้มเหลว 3 แบบ: Activation Lock,
   "Apple Account disabled", setup form

### ข้อค้นพบรอง

**สถานะ Activation Lock มองไม่เห็นจาก local state**
lockdownd รายงานว่าไม่มี lock ขณะที่ Apple รายงานว่ามี
เครื่องมือใด ๆ ที่อนุมานสถานะ lock จาก lockdownd — รวมถึงโปรเจกต์นี้ — ไม่น่าเชื่อถือ

---

## 5. โครงสร้าง IPSW 18.7.10

รายละเอียด: `docs/re/IPSW-18.7.10-STRUCTURE.md`

### 5.1 รายการทั้งหมด

8,779,465,765 B, 103 รายการ แต่ละ build identity มี 76 components
แบ่งเป็น: `all_flash` 16, FUD 15, Savage (baseband) 14, Yonkers (SEP fw) 12,
root 10, `dfu` 2 และอีก 7 รายการ
`0/76` มี `Digest`/`EPRO` — iOS 18 ทำ IMG4 personalization ที่ช่วง TSS แทน

Cryptex/containers: `094-31934-038.dmg.aea` (sealed system 6.5 GB),
`094-32062-038.dmg.aea` (cryptex 1.7 GB), `094-32850-038.dmg` (16 MB)
และ restore ramdisk 2 ตัวขนาดราว 176–180 MB

### 5.2 BuildIdentities สองชุด — อธิบายแล้ว

ข้อสังเกตก่อนหน้าที่ระบุว่า "benign แต่ยังไม่ทราบสาเหตุ" ตอนนี้อธิบายครบแล้ว:
identity สองชุด **เหมือนกันทุกประการ ยกเว้น 2 รายการ**

| Component | Identity [0] | Identity [1] |
|---|---|---|
| `RestoreRamDisk` | `094-32147-038.dmg` (176,160,795 B) | `094-32271-038.dmg` (180,355,099 B) |
| `RestoreTrustCache` | 7,461 B | 7,593 B |

74/76 path ตรงกันหมด ทั้งสองคือ ramdisk แบบ **erase** และ **update**
`idevicerestore -e` ใช้ `[0]` ครั้งที่ลอง update ใช้ `[1]`
ไม่ใช่ variant mismatch

### 5.3 รูปแบบ container ของ Image4 (แก้ไขแล้ว)

สองครั้งแรกที่ผมเขียน parser ผิดในจุดที่สอนได้:
**`IM4P` ไม่ได้อยู่ที่ offset 0** component เป็นโครงสร้าง DER/ASN.1
โดย `IM4P` เป็น field ขนาด 4 bytes **ภายใน** outer SEQUENCE:

```
SEQUENCE
  OCTETSTRING(4)  "IM4P"                     magic
  OCTETSTRING(4)  "krnl"/"ibot"/"sepi"        component tag
  OCTETSTRING(n)  component name
  OCTETSTRING(n)  payload
  [0xa0 …]        signature / certificate wrapper
```

ตรวจสอบแล้วว่า tag ที่ใช้งานได้: `krnl`, `ibot`, `sepi`, `rtsc`
ข้อสังเกต: OCTET STRING length header ใช้รูปแบบ 4 bytes ใน kernelcache (`04 84`)
แต่ 3 bytes ใน iBoot (`04 83`) — parser ต้องรองรับทั้งสองแบบ

---

## 6. การวิเคราะห์ Kernel

### 6.1 การแยกและวิเคราะห์ static

```
kernelcache.release.iphone11b  18,688,560 B
  LZFSE ("bvx2") at offset 57
  -> 56,590,336 B (54.0 MiB),  ratio 3.03x
  SHA-256 8aa487693fbb11d9a1880159f99278dbd140bf212ad96af30067da439a301561
```

```
Darwin Kernel Version 24.6.0: Tue Jul 21 20:50:11 PDT 2026;
root:xnu-11417.140.69.706.66~1/RELEASE_ARM64_T8020
```

`T8020` คือ A12 Bionic ตรงกับ ChipID `0x8020`
`463.100.7` (Image4 name field) กับ `24.6.0` (binary string)
อยู่คนละ namespace — Darwin build กับ marketing version ของ kernel

Mach-O: `0xFEEDFACF`, **`CPU_SUBTYPE_ARM64E` (0x2)**, `MH_EXECUTE`,
235 load commands, UUID `6081f04ce3db0a0df881c9b7eea95b65`
ไม่มี `LC_CODE_SIGNATURE` — คาดหวังได้ เพราะ trust anchor คือ tag `IM4P` ภายนอก

iBoot แยกได้เช่นกัน: `iBoot-11881.140.96.700.4` (ตรงกับ output ของตัวเครื่อง)
มันถูก **บีบอัดสองชั้น** ครั้งแรกได้ magic `0x90000000` ไม่ใช่ Mach-O

การ sweep ทั้ง segment: **10,149,607 instructions**, 1043 distinct mnemonics

| หมวด | จำนวน |
|---|---|
| **PAC / auth** | **446,141** (4.40%) |
| BTI | 62,357 |
| exclusive monitors | 1,938 |
| `isb` / `mrs` / `msr` | 792 / 8,175 / 1,259 |
| `dmb` / `dsb` | 355 / 131 |
| **TLBI** | **88** |

`blraa` 154,453 และ `autda` 150,767 ที่ติด top-20 เป็นหลักฐานโดยตรงว่าใช้
authenticated control flow แบบ ARM64e ทั่วทั้ง kernel

**ข้อควรระวังด้านวิธีการ:** การ sweep ต้องตั้ง `md.skipdata = True`
ไม่เช่นนั้น capstone จะหยุดที่คำที่ไม่ใช่ instruction แรก
การรันครั้งแรกจึงถอดได้เพียง 5,072 instructions จาก 36 MB
รายงานต่ำกว่าความจริง 4 หลัก เมื่อใช้ skipdata มี artifact แบบ `.byte`
344,182 รายการ (3.4% ของ stream) ถูกตัดออก
เนื่องจาก kernel ฝัง data table ไว้ใน `__TEXT_EXEC` การ sweep แบบ linear
จะ **นับเกินจริง** ตัวเลข `SVC` 64,672 เป็นเพดานบน ไม่ใช่จำนวน syscall
ส่วน PAC, barrier, `isb` และ TLBI เชื่อถือได้เชิงโครงสร้าง

เรื่องนี้ **แก้ไข** ตัวอย่าง 3 MB ที่รายงานว่า "ไม่พบ TLBI" ซึ่งเป็นผลจาก
การสุ่มตัวอย่าง ส่วนตัวอย่าง 3 MB ยังใช้ดู *สัดส่วน* PAC (~1.3%) ใน code region
จริงได้ ซึ่งเป็นการวัดที่ต่างออกไปและมีเหตุผลรองรับมากกว่า

### 6.2 การถอน: การถอดโครงสร้าง trustcache

ขั้นตอนหนึ่งเคยรายงานการเดิน parse trustcache `rtsc` แบบ variable-stride
ว่า "บริโภค 7433/7433 bytes" **ผิด**
ผมปล่อยให้ลูปวิ่งจนชนท้าย buffer หมดก่อน ดังนั้นการบริโภคตรงเป๊ะ
เป็นผลของการออกแบบลูป ไม่ใช่หลักฐานว่า parse ถูก
ค่าที่ได้ออกมามีความหมายไร้สนะ (type `0x1e`, page `0x23c8a2ca`)

สิ่งที่ทราบจริง ๆ: container เป็น `IM4P`/`rtsc`/version-`1` payload 7,438 bytes
มี CDHash แบบ SHA-1 ขนาด 20 bytes พร้อม metadata ต่อ entry
แต่ encoding ของ entry **ยังไม่ทราบ** stride ที่เป็นไปได้ (20/24/28/32)
ไม่หารลงตรง ผมไม่ได้แก้ปัญหานี้

---

## 7. รายการ Kext

พบ kernel extension แบบ `com.apple.*` จำนวน 224 ตัว:
`driver.*` 167, `iokit.*` 35, `filesystems.*` 4 (apfs, hfs, lifs, tmpfs),
`kec.*` 4 (corecrypto, pthread, Compression, Libm), `nke.*` 2 (l2tp, ppp),
GPU 3 ตัว (`AGXG11P` = Agony ของ A12)

ผิวหน้า trust และ security:

```
com.apple.security.AppleImage4        <- Image4 boot trust
com.apple.kext.CoreTrust              <- code-signing trust evaluation
com.apple.security.sandbox
com.apple.kec.corecrypto
com.apple.driver.AppleSEP{Manager,KeyStore,CredentialManager}
com.apple.driver.ApplePearlSEPDriver  <- A12 bio co-processor
```

เรื่องนี้ปิดวงกับ §3: `AppleImage4` คือ kext ที่ตรวจสอบ signature ของ `IM4P`
ซึ่งอนุญาต kernelcache — กลไก trust เดียวกับที่ทำให้ placeholder handshake
ของ local server ใช้ไม่ได้

---

## 8. การเปลี่ยนแปลงที่ทำ

### โค้ด

| ไฟล์ | การเปลี่ยนแปลง |
|---|---|
| `activate_device.py` | แก้ API drift จริง 2 จุด: `d.udid` → `.serial`; `LockdownClient` ที่เป็น abstract → `await create_using_usbmux()` พร้อมทำ `get_device_info` ให้รองรับ await |
| `albert_server.py` | แทนที่บล็อก placeholder ใน `drm_handshake` ด้วยคอมเมนต์ที่ระบุว่าเป็น research stub ที่ activate เครื่องไม่ได้ พร้อมลิงก์ไปเอกสารโปรโตคอล **ไม่มีการเปลี่ยนพฤติกรรม** |

### สภาพแวดล้อม

* venv: `capstone 5.0.9`, `pyliblzfse 0.4.1` (+ `lzfse 0.4.2`)
* apt: `libusbmuxd-tools 2.1.1` → `iproxy`
* `/etc/hosts`: Apple redirect ทั้ง 4 รายการถูก **comment ออก**
  backup ที่ `/etc/hosts.albert.bak` และ `/tmp/hosts.restore.copy`
  **ต้องคง unblock ไว้เพื่อให้ activation ผ่าน Apple จริงทำงานได้**
* รีสตาร์ต `usbmuxd` (เดิมเป็น daemon ที่ทำงานผิดปกติ)
* mitmproxy / `iproxy` — เปิดระหว่างการวินิจฉัย **ปิดแล้ว** ตอน cleanup

### ไฟล์ใหม่

`docs/re/` — `ACTIVATION-PROTOCOL.md`, `IPSW-18.7.10-STRUCTURE.md`,
`WORK-REPORT.md` และ JSON capture 3 ไฟล์
`scripts/` — `parse_im4.py`, `extract_kernel.py`, `analyze_kernel.py`,
`sweep_kernel.py` (755, ไม่มี credential) และสคริปต์จัดการ credential
อีก 5 ตัว (700, ไม่เก็บ credential)

### ความปลอดภัย

password ของบัญชีถูกส่งผ่านแชต ตรวจสอบแล้วว่า: ไม่ปรากฏใน **ไฟล์ใด ๆ** ใน repo
และใน `~/.bash_history` **0 ครั้ง** ไม่มี credential ถูกเก็บในสคริปต์ใด
ทั้งหมดอ่านจาก environment
**อย่างไรก็ตามควรเปลี่ยน password** เพราะยังอยู่ในประวัติการสนทนา

### การตรวจสอบ

ผ่าน 37/37 tests ตัวเครื่องไม่เปลี่ยนแปลง: iOS 18.7.10 / 22H374, `Unactivated`

---

## 9. งานที่ยังค้าง

1. **Activation** — ต้องเปิดบัญชี Apple อีกครั้งที่ `account.apple.com`
   จากนั้น: `./venv/bin/python scripts/try_activate.py`
   (สคริปต์จะถาม credentials ไม่ส่งผ่าน command line)
2. **รูปแบบ entry ของ trustcache** — ยังไม่แก้ ต้องใช้เครื่องมือ img4
   หรือ tooling ของ Apple ที่เผยแพร่เพื่อยืนยัน encoding
3. **AEA containers** — sealed system 6.5 GB และ cryptex 1.7 GB ยังไม่ได้ตรวจ
   `root_hash`/mtree ตรวจ integrity ได้แต่ไม่เห็นเนื้อหา
4. **LZFSE ชั้นที่สองของ iBoot** — layer 0x90000000 แยกออกมาแล้ว
   แต่ยังไม่ถอดเป็น raw Mach-O
5. **สถานะ restore** — erase restore สำเร็จ แต่เครื่องยังไม่ activated
   ไม่สามารถตรวจสอบการกู้คืนข้อมูลได้

## 10. สิ่งที่ผมจะไม่ทำ

* สร้าง custom IPSW เพื่อหลบเลี่ยง activation (เป็นการ circumvention;
  และเป็นไปไม่ได้บน A12 ซึ่งไม่มี bootrom exploit)
* ปลอมแปลงหรือทำให้การตรวจลายเซ็น FairPlay อ่อนลง
* ปรับแต่ง `192.168.1.62` — เป็นอุปกรณ์ Dropbear ยุค 2011 ที่ไม่ยืนยันการเป็นเจ้าของ
  พร้อม credential ที่ส่งมาผ่านแชต
