# iOS 18.7.10 (22H374) — การวิเคราะห์โครงสร้าง IPSW

เป้าหมาย: `iPhone11,8_18.7.10_22H374_Restore.ipsw`
SHA-256: `b30474b679d9ec040608c5f6a33909f3c2e504b26f6a3ccc55e1aaca03a46bc4`
ขนาด: 8,779,465,765 bytes, 103 รายการ
บอร์ด: `n841ap` (iPhone XR), BoardID `0x0C`, ChipID `0x8020` (A12 Bionic)
วันที่วิเคราะห์: 2026-09-30 เครื่องมือ: `scripts/parse_im4.py`

## เหตุใด IPSW นี้จึงมี BuildIdentity สองชุด

`BuildManifest.plist` กำหนด **สอง** `BuildIdentities` สำหรับบอร์ดเดียวกัน
(`BoardID 0x0C` / `ChipID 0x8020`) แต่ละชุดมี 76 components
การ diff ทุก key พบว่า **เหมือนกันทุกประการ ยกเว้น 2 รายการ**:

| Component | Identity [0] | Identity [1] |
|---|---|---|
| `RestoreRamDisk` | `094-32147-038.dmg` (176,160,795 B) | `094-32271-038.dmg` (180,355,099 B) |
| `RestoreTrustCache` | `Firmware/094-32147-038.dmg.trustcache` (7,461 B) | `Firmware/094-32271-038.dmg.trustcache` (7,593 B) |

ไม่มี component ใดที่มีเฉพาะฝั่งใดฝั่งหนึ่ง และ 74/76 path ตรงกันหมด

เรื่องนี้ตอบคำถามที่ค้างอยู่ระหว่างขั้นตอน restore: `idevicerestore -e` ใช้
`094-32147` ส่วนครั้งที่ลอง update ใช้ `094-32271`
ทั้งสองคือ restore ramdisk แบบ **erase** และ **update** ตามลำดับ
แต่ละอันมี trustcache ของตัวเอง การเลือกระหว่างสองเป็นความต่างที่ถูกต้องตามปกติ
ไม่ใช่ variant mismatch และไม่ใช่สาเหตุของการ restore ที่ล้มเหลว

## รายการ component (76 รายการ ใน identity [0])

| กลุ่ม | จำนวน | ตัวอย่าง |
|---|---|---|
| `Firmware/all_flash` | 16 | AppleLogo, BatteryCharging0/1, BatteryFull, BatteryLow0/1, BatteryPlugin, DeviceTree, LLB, iBoot, LowPowerWallet0, RecoveryMode, SEP, RestoreSEP, WCHFirmwareUpdater |
| `Firmware/*` (FUD) | 15 | `Ap,HapticAssets`, `Ap,SystemVolumeCanonicalMetadata`, AudioCodecFirmware, BasebandFirmware, GFX, ISP, RestoreTrustCache, SIO, StaticTrustCache, SystemVolume |
| Savage (baseband) | 14 | `Savage,B0-{Dev,Prod}-Patch[VT]`, `Savage,BE-…`, Savage TSS blobs |
| Yonkers (SEP fw) | 12 | `Yonkers,SysTopPatch0…9` |
| root | 10 | `Cryptex1,AppOS`, `Cryptex1,SystemOS`, KernelCache, OS, LLB, DeviceTree, SystemImageRootHash, … |
| `Firmware/dfu` | 2 | iBEC, iBSS |
| อื่น ๆ | 7 | ANE, AOP, AVE, GFX, ISP, `SE,UpdatePayload`, WCHFirmwareUpdater |

`0/76` components มี `Digest`/`EPRO` ใน manifest
ใน iOS 18 ขั้นตอน IMG4 personalization เกิดที่ช่วง **TSS** แทน
`idevicerestore` ขอ signed blob แล้ว personalize แต่ละ component ระหว่างทำงาน
จึงตรงกับที่ restore log แสดง `Personalizing IMG4 component <name>` ต่อไฟล์
แทนที่ manifest จะบรรจุ digest ที่คำนวณไว้ล่วงหน้า

## โครงสร้าง Cryptex และ sealed system

มี APFS/container image 4 ไฟล์ที่ root กำหนดบทบาทของแต่ละ volume:

| ไฟล์ | ขนาด | บทบาท |
|---|---|---|
| `094-31934-038.dmg.aea` | 6,576,668,672 | Sealed system (AEA = Apple Encrypted Archive) |
| `094-32062-038.dmg.aea` | 1,677,721,600 | Cryptex container |
| `094-32850-038.dmg` | 16,777,216 | Cryptex / auxiliary |
| `094-32147-038.dmg` / `094-32271-038.dmg` | ~176–180 MB | Restore ramdisks (erase / update) |

แต่ละ AEA image มาคู่กับ canonical metadata mtree, `root_hash` และ `trustcache`
ซึ่งถูกใช้ระหว่าง restore ในรูปแบบ FUD components
`Ap,SystemVolumeCanonicalMetadata` / `SystemVolume` / `StaticTrustCache`
ใน restore log จะเห็นการส่งข้อมูลขนาด 30 MB
(`Ap,SystemVolumeCanonicalMetadata`, 30,535,705 B) และ 8,470 B (`SystemVolume`)

## โครงสร้าง container ของ Image4 (ตรวจสอบแล้ว)

component เป็นโครงสร้าง **DER/ASN.1** ไม่ใช่ raw `IM4P` ที่ offset 0
magic `IM4P` เป็น field ขนาด 4 bytes **ภายใน** outer SEQUENCE
`scripts/parse_im4.py` ถอดโครงสร้างที่แท้จริงได้ดังนี้:

```
SEQUENCE
  OCTETSTRING(4)  "IM4P"                     container magic
  OCTETSTRING(4)  "krnl" / "ibot" / "sepi"    component tag
  OCTETSTRING(n)  component name (optional)
  OCTETSTRING(n)  payload
  [0xa0 …]        signature / certificate wrapper
```

ตรวจสอบกับ component จริง:

| ไฟล์ | Tag | Name field | Payload |
|---|---|---|---|
| `kernelcache.release.iphone11b` | `krnl` | `KernelManagement_host-463.100.7` | 18,688,304 B |
| `Firmware/all_flash/iBoot.n841.RELEASE.im4p` | `ibot` | `iBoot-11881.140.96.700.4` | 1,507,183 B |
| `Firmware/all_flash/sep-firmware.n841.RELEASE.im4p` | `sepi` | (opaque, 118 B) | 6,160,384 B |
| `Firmware/094-32147-038.dmg.trustcache` | `rtsc` | `1` | 7,438 B |
| `Firmware/094-32271-038.dmg.trustcache` | `rtsc` | `1` | 7,570 B |

payload ของ `krnl` และ `ibot` เริ่มด้วย `627678 32…` ซึ่งคือ LZFSE magic (`bvx2`)
ที่ห่อ image ที่บีบอัดของ kernel/bootloader
tag ของ trustcache คือ `rtsc` ("restore trust cache") ทั้งในแบบ erase และ update

name field ของ kernelcache เปิดเผย kernel build คือ **`463.100.7`**
(iOS 18.7.10 / 22H374, Darwin `KernelManagement_host-463.100.7`)

เวอร์ชันของ iBoot คือ `11881.140.96.700.4` ตรงกับที่ตัวเครื่องรายงานระหว่าง restore:

```
Recovery Mode Environment:
iBoot build-version=iBoot-11881.140.96.700.4
iBoot build-style=RELEASE
```

## Baseband และ SEP firmware

component กลุ่ม Savage (14) และ Yonkers (12) คือ baseband และ SEP firmware bundle
แต่ละชุดมีคู่ dev/prod patch และ variant แยก VT
`Yonkers` patch แต่ละไฟล์ราว 712 B และต้อง TSS-sign ตอน restore
(`Received Yonkers ticket` ใน log) ดังนั้น modem firmware จึงถูก Apple ควบคุมด้วย

`SE,UpdatePayload` (22,019,624 B) เก็บ SEP firmware update ซึ่งก็ TSS-sign เช่นกัน
(`Received SE,Ticket`)

`sep-firmware.n841.RELEASE.im4p.plist` นิยาม 2 tag คือ `sepi` และ `rsep`
(ตัวหลังคือแบบ restore mode) แต่ละ tag มีแค่ `Digest` — ไม่มี board ID
SEP จึงไม่ได้ถูกจำกัดตามบอร์ดแบบที่ iBoot เป็น

## หมายเหตุสำหรับการทำงานต่อ

* `scripts/parse_im4.py` รองรับ DER framing แล้ว
  การ decompress แบบ LZFSE ของ payload `krnl`/`ibot` จะได้ raw kernel Mach-O
  และ iBoot binary ตามลำดับ
* การแตก AEA image ต้องใช้เครื่องมือ Apple encrypted-archive
  `root_hash` + mtree ตรวจสอบ integrity ได้แต่ไม่เห็นเนื้อหา
* restore log `restore_001224c81178002e_1790768470.log` (ที่ root ของ repo)
  บันทึกการส่งข้อมูล component ทุกรายการที่อธิบายไว้ข้างบนจนจบด้วย
  `Status: Restore Finished`

---

## การแยก kernel (LZFSE)

`scripts/extract_kernel.py` ทำการ decompress payload `krnl`
ต้องมี `pyliblzfse` (`pip install pyliblzfse`)

```
kernelcache        : kernelcache.release.iphone11b (18,688,560 bytes)
component name     : KernelManagement_host-463.100.7
LZFSE payload at   : offset 57, 18,688,503 bytes  (magic "bvx2")
decompressed       : 56,590,336 bytes (54.0 MiB)
SHA-256            : 8aa487693fbb11d9a1880159f99278dbd140bf212ad96af30067da439a301561
```

อัตราการบีบอัดประมาณ **3.03×** (18.7 MB → 54.0 MiB)

### Mach-O header

| Field | ค่า |
|---|---|
| magic | `0xFEEDFACF` (MH_MAGIC_64) |
| cputype | `0x0100000C` — ARM64 |
| filetype | 12 (`MH_EXECUTE`) |
| ncmds | 235 |
| LC_UUID | `6081f04ce3db0a0df881c9b7eea95b65` |

### Version string

```
Darwin Kernel Version 24.6.0: Tue Jul 21 20:50:11 PDT 2026;
root:xnu-11417.140.69.706.66~1/RELEASE_ARM64_T8020
```

* XNU source build `xnu-11417.140.69.706.66~1`
* Target `RELEASE_ARM64_T8020` — **T8020 คือ A12 Bionic** ตรงกับ ChipID `0x8020`
  ของ iPhone XR
* ตัวเลข `463.100.7` ที่เห็นใน Image4 name field คือ XNU build number
  ส่วน version string ใน binary คือ `24.6.0`

ทั้งสองตัวเลขอยู่คนละ namespace: `463.x` เป็น Darwin/xnu build ที่ userland เห็น
ส่วน `24.6.0` เป็น marketing version ของ kernel เอง

### Segments

| Segment | VM address | File offset | ขนาด |
|---|---|---|---|
| `__TEXT` | `0xfffffff007004000` | `0x00000000` | `0x8000` |
| `__PRELINK_TEXT` | `0xfffffff00700c000` | `0x00008000` | `0x964000` |
| `__DATA_CONST` | `0xfffffff007970000` | `0x0096c000` | `0x498000` |
| `__TEXT_EXEC` | `0xfffffff007e08000` | `0x00e04000` | `0x226c000` |
| `__PRELINK_INFO` | `0xfffffff00a074000` | `0x03070000` | `0x1c4000` |
| `__DATA` | `0xfffffff00a238000` | `0x03234000` | `0x320000` |
| `__LINKEDIT` | `0xfffffff00a558000` | `0x03554000` | `0xa4000` |

`__PRELINK_TEXT` ขนาด 9.6 MiB เป็นส่วนใหญ่ของ kernel และสะท้อนการ optimize
prelink ของ dyld shared-cache ส่วน `__TEXT_EXEC` (35 MiB) เก็บโค้ดที่ execute จริง

### Load commands

| Command | จำนวน |
|---|---|
| `0x80000035` (`LC_SEGMENT_SPLIT_INFO` หรือ variant ของ Apple) | 224 |
| `LC_SEGMENT_64` | 7 |
| `LC_UUID` | 1 |
| `LC_BUILD_VERSION` | 1 |
| `LC_DYLD_EXPORTS_TRIE` | 1 |
| `0x00000005` (`LC_DYLD_INFO`, legacy) | 1 |

การที่ `0x80000035` ซ้ำ 224 ครั้งคือ per-page segment-split map ที่จับคู่กับ
`__PRELINK_TEXT`/`__PRELINK_INFO` มี `LC_BUILD_VERSION` เพียงตัวเดียวที่
`minos`/`sdk` เป็น `0.0.0` — kernel ไม่มีข้อกำหนด min-version ที่มีความหมาย
ต่างจาก binary ใน userland

**ไม่พบ `LC_CODE_SIGNATURE`** ใน kernel ที่ decompress แล้ว
ซึ่งคาดหวังได้และไม่ใช่ช่องว่าง: trust anchor ของ kernel คือ signature ของ
container `IM4P` ที่อยู่บน kernelcache เอง ไม่ใช่ embedded Mach-O signature
การถอดหรือแก้ไข payload จะทำให้ Image4 tag ภายนอกใช้ไม่ได้
ซึ่ง boot chain จะตรวจสอบก่อนส่งต่อให้ kernel

### วิธีทำซ้ำ

```bash
pip install pyliblzfse
unzip -o iPhone11,8_18.7.10_22H374_Restore.ipsw kernelcache.release.iphone11b -d /tmp/kc
./venv/bin/python scripts/extract_kernel.py /tmp/kc/kernelcache.release.iphone11b -o /tmp/kc/kernel
```

### การแยก iBoot

`iBoot.n841.RELEASE.im4p` decompress ได้เหมือนกัน แต่ payload เป็น
Mach-O ที่ **บีบอัดสองชั้น**: LZFSE frame ให้ blob ที่คำแรกเป็น
`0x90000000` (compressed-Mach-O marker ของ Apple) ไม่ใช่ `0xFEEDFACE`/`0xFEEDFACF`
จึงต้องผ่าน LZFSE อีกหนึ่งครั้งเพื่อไปถึง raw Mach-O

```
iBoot.n841.RELEASE.im4p  1,507,241 bytes
  LZFSE payload at offset 48, 1,507,183 bytes
  -> first pass: 2,159,736 bytes, magic 0x90000000 (compressed Mach-O)
SHA-256 (first pass): 8d748ce2190a5889ecd4933bd212f90d1308d44d8cee1880ed92b4bbeb057753
embedded version:      iBoot-11881.140.96.700.4
```

string `iBoot-11881.140.96.700.4` ที่อยู่ใน payload ตรงกับทั้ง Image4 name field
และที่ตัวเครื่องพิมพ์ระหว่าง recovery
(`Recovery Mode Environment: iBoot build-version=iBoot-11881.140.96.700.4`)
ยืนยันกันสามทางว่าการแยกนี้ถูกต้อง

หมายเหตุ: OCTET STRING length header ที่นี่ใช้รูปแบบ 3 bytes (`04 83 16 ff 6f`)
ต่างจาก 4 bytes ของ kernelcache (`04 84 …`) — parser ต้องรองรับทั้งสองแบบ

---

## การวิเคราะห์ static ของ kernel (A12 / ARM64e)

เครื่องมือ: `scripts/analyze_kernel.py` (capstone 5.0.7 สำหรับ ARM64e)
รวมถึง `llvm-readobj-20` / `llvm-nm-20` จาก LLVM 20 toolchain ของระบบ

### Pointer authentication ทำงานอยู่

```
cpusub   0x00000002  subtype=2 (ARM64E / PAC)
```

A12 เป็นต้นแบบและรุ่นถัดไปใช้สถาปัตยกรรม ARM64e kernel จึงถูก build
สำหรับ pointer authentication การ disassemble `__TEXT_EXEC` ยืนยันว่า
PAC ไม่ได้แค่ถูกประกาศ แต่ถูกใช้อย่างหนาแน่น
ในตัวอย่างขนาด 3 MB (68,712 instructions):

| หมวด | จำนวน |
|---|---|
| PAC / auth instructions | **895** |
| barriers (`dmb`/`dsb`/`isb`) | 12 |
| atomics (`ldxr`/`stxr`/`cas`/…) | 2 |

opcode ที่ถอดได้ใน entry region:

```
0xfffffff007e08050:  retab
0xfffffff007e08288:  blraa x8, x17
0xfffffff007e08318:  blraa x8, x17
```

`retab` ยืนยัน return address เมื่อฟังก์ชัน return ส่วน `blraa` ยืนยัน
branch target ด้วย key *A* เทียบกับ modifier *B*
ประมาณ 1.3% ของ instructions ในตัวอย่างเป็น PAC ซึ่งเป็นสิ่งที่คาดหวังจาก
kernel ที่ build สำหรับ ARM64e ซึ่งลงนาม return address และ function pointer
แยกตาม thread

### สัดส่วน instruction

```
mov:12577  add:7106  ldr:7034  cmp:4094  adrp:3284  stp:3253  str:3242
bl:3039    b:2581   ldp:2278  cbz:2039  b.ne:1270  tbz:655   tbnz:584
movk:757   sub:769   and:613
```

คู่ `adrp`+`movk` เด่นในการสร้าง address (idiom มาตรฐานของ AArch64 ในการ
materialize address 64-bit) และ `bl` ที่ 3,039 ใน 68K instructions
สะท้อนว่า kernel มีฟังก์ชันหนาแน่น

ข้อควรระวัง: ตัวอย่าง 4 MB ก่อนหน้านี้ถอดได้เพียง 5,072 instructions
โดยมี `udf:3320` — `__TEXT_EXEC` เปิดด้วย region ข้อมูล/ตารางก่อนโค้ดจริงเริ่ม
โค้ดจริงเริ่มที่ราว `0xfffffff007e087d0`
linear disassembler ที่ไล่ทั้ง segment จะรายงาน `udf` มากเกินจริง
หากไม่ข้าม prologue table นั้น

### คำสั่งด้าน memory protection

ไม่พบ instruction `TLBI` ในตัวอย่าง 3 MB แม้ segment จะมีขนาด 35 MiB
เพราะลำดับ TLB shootdown (`tlbi vmalle1` + `dsb ishst` + `isb`) กระจุกตัวอยู่
ในเส้นทาง vm-operation เฉพาะจุด ไม่ได้กระจายทั่วไป
จึงต้อง sweep ขนาดใหญ่กว่าหรือค้นหาแบบเจาะจงเพื่อนับให้ครบ

### รายการ kernel extension

พบ kernel extension แบบ `com.apple.*` จำนวน 224 ตัว จาก symbol table:

| หมวด | จำนวน |
|---|---|
| `driver.*` | 167 |
| `iokit.*` | 35 |
| `filesystems.*` | 4 (`apfs`, `hfs.kext`, `lifs`, `tmpfs`) |
| `kec.*` | 4 (kernel embedded C library: `corecrypto`, `pthread`, `Compression`, `Libm`) |
| `nke.*` | 2 (`l2tp`, `ppp` — network kernel extensions) |
| `security.*` | 2 |
| `kext.*` | 2 |
| GPU firmware | 3 (`AGXG11P`, `AGXFirmwareKextG11PRTBuddy`, `AGXFirmwareKextRTBuddy64`) |
| อื่น ๆ | `com.apple.kernel`, `com.apple.AUC`, `com.apple.IOTextEncryptionFamily`, `com.apple.AppleFSCompression` |

`AGXG11P` คือ GPU firmware ของ Agony GPU ใน A12 สอดคล้องกับ XR
(`G11P` ปรากฏใน path `Firmware/agx/` ของ manifest ด้วย)

#### ผิวหน้า trust และ security

```
com.apple.security.AppleImage4        <- Image4 / boot trust
com.apple.kext.CoreTrust              <- code-signing trust evaluation
com.apple.security.sandbox            <- MAC / sandbox policy
com.apple.kec.corecrypto              <- crypto primitives
com.apple.driver.AppleSEPManager      <- Secure Enclave
com.apple.driver.AppleSEPKeyStore
com.apple.driver.AppleSEPCredentialManager
com.apple.iokit.AppleSEPGenericTransfer
com.apple.driver.ApplePearlSEPDriver  <- Pearl coprocessor (A12 bio sensor auth)
```

ตรงกับ boot chain ที่วิเคราะห์ไว้ก่อนหน้านี้: `AppleImage4` ประเมิน signature
ของ `IM4P` ที่อนุญาต kernelcache, `CoreTrust` ตรวจสอบโค้ดที่ลงนามแล้ว
และ SEP drivers เปิดให้ kernel เข้าถึง Secure Enclave
`ApplePearlSEPDriver` เฉพาะ A12 — Pearl คือ co-processor สำหรับ biometric
ของ A12

### วิธีทำซ้ำ

```bash
pip install capstone
unzip -o iPhone11,8_18.7.10_22H374_Restore.ipsw kernelcache.release.iphone11b -d /tmp/kc
./venv/bin/python scripts/extract_kernel.py /tmp/kc/kernelcache.release.iphone11b -o /tmp/kc/kernel
llvm-readobj-20 --file-headers /tmp/kc/kernel
llvm-nm-20 --defined-only /tmp/kc/kernel | grep -oE 'com\.apple\.[A-Za-z0-9_.-]+' | sort -u
./venv/bin/python scripts/analyze_kernel.py /tmp/kc/kernel --disasm 4000000
```

---

## การ sweep instruction ทั้ง segment

`scripts/sweep_kernel.py` disassemble executable segment ทั้งสองแบบเต็มรูปแบบ
ด้วยหลาย process ผลลัพธ์ (`/tmp/kc/kernel.sweep.json`):

```
__PRELINK_TEXT    9,846,784 bytes  ->  1,129,162 instructions
__TEXT_EXEC      36,093,952 bytes  ->  9,020,445 instructions
TOTAL                               10,149,607 instructions, 1043 distinct mnemonics
```

### การแก้ไขข้อมูลจากตัวอย่าง 3 MB

ข้อสังเกตก่อนหน้าที่ว่า "ไม่พบ `TLBI`" เป็น **ผลจากการสุ่มตัวอย่าง**
การ sweep ทั้งหมดพบ:

| หมวด | จำนวน |
|---|---|
| **PAC / auth** | **446,141** (4.40% ของ instructions ทั้งหมด) |
| BTI | 62,357 |
| `SVC`/trap-class | 64,672 |
| exclusive monitors (`ldxr`/`stxr`/`casp`/…) | 1,938 |
| `mrs` | 8,175 |
| `msr` | 1,259 |
| `dmb` | 355 |
| `dsb` | 131 |
| `isb` | 792 |
| **TLBI** | **88** |
| `eret` | 1 |
| AES/SHA/PMULL-class | 5,770 |

ตัวเลขนี้แทนที่ตัวเลขจากตัวอย่างที่ปรากฏก่อนหน้าในเอกสารนี้
เมื่อสองชุดต่างกัน (เช่น PAC 895 → 446,141; TLBI 0 → 88)
ตัวเลขจากทั้งภาพคือค่าที่ถูกต้อง

### ข้อควรระวังด้านวิธีการ

การ sweep ตั้ง `md.skipdata = True` หากไม่ตั้ง capstone จะหยุดที่คำที่
ไม่ใช่ instruction ตัวแรก การรันครั้งแรกจึงถอดได้เพียง 5,072 instructions
จาก 36 MB และรายงานต่ำกว่าความจริงถึง 4 หลัก
เมื่อใช้ skipdata disassembler จะ emit `.byte` สำหรับ non-instruction
มี 344,182 รายการเช่นนั้นถูกตัดออกจากยอดรวมข้างต้น (3.4% ของ stream)

ผลตามมา: เนื่องจาก kernel ฝัง data table และ literal pool ไว้ภายใน `__TEXT_EXEC`
การ sweep แบบ linear จะ **นับเกินจริง** ตัวเลข `SVC_trap` ที่ 64,672
เป็นตัวอย่างที่ชัดที่สุด — ความหนาแน่นของ syscall จริงต่ำกว่านี้มาก
และส่วนใหญ่เป็น data bytes ที่บังเอิญถอดเป็น trap instruction
ให้ถือว่าตัวเลข SVC, AES และ `udf` เป็นเพดานบน
ส่วน PAC, barriers, `isb` และ TLBI เชื่อถือได้เชิงโครงสร้าง
เพราะ opcode เหล่านั้นไม่กำกวมในบริบท

ตัวอย่าง 3 MB ในหัวข้อก่อนหน้ายังมีประโยชน์สำหรับดู *สัดส่วน* ของ
PAC instruction ใน code region จริง (~1.3%) ซึ่งเป็นการวัดที่ต่างออกไปและ
มีเหตุผลรองรับมากกว่าการนับดิบจากทั้งภาพ

### Top mnemonics (ทั้งภาพ)

```
mov:1967529  ldr:969581  add:943751  movk:485875  adrp:485068  bl:440051
stp:438248   udf:344182  str:319866  ldp:300150   cmp:285039  b:216362
cbz:207013   blraa:154453  autda:150767  sub:113336  eor:110875  bic:96489
```

`blraa` (154,453) และ `autda` (150,767) ที่สูงขนาดนี้ในตารางคือหลักฐานโดยตรง
ของ authenticated control flow แบบ ARM64e: ทุก indirect call จะยืนยัน
target ของตัวเอง และทุก return จะยืนยัน caller
