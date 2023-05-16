% TRIAGE LOG

## SETUP

### Admin cmd

```
usbipd wsl list
usbipd wsl attach --busid 1-12
usbipd bind --force --busid 1-12
```

### Generate and upload

```
adb push gef-scripts /data/local/tmp
python3 fuzzing/triage.py --target com.skt.smartbill --target_function Java_com_ubikey_jni_UbikeyJni_jGetUser@0 --debug --device RF8N12BM5VN
```

### In adb shell

```
export GEF_RC=/data/local/tmp/gef.rc
export PATH=/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/home/AFLplusplus-AndroidPatches:$PATH
```

### In gdb/gef

```
set pagination off
```

# com.skt.smartbill

## `Java_com_ubikey_jni_UbikeyJni_jGetUser@0`

```
python3 fuzzing/triage.py --target com.skt.smartbill --target_function Java_com_ubikey_jni_UbikeyJni_jGetUser@0 --debug --device RF8N12BM5VN
```

### BT5

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.skt.smartbill/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.skt.smartbill memory reproduced_crashes/bt_5/output_R58MA2XTBEB_18:59-03-03-2023_default_id:000002,sig:11,src:000121,time:7294,execs:1869,op:havoc,rep:2 0 0
```

#### gdb commands

```
r
b *Clear_OBJECT_IDENTIFIER+44
c
c
c
scudo chunk $x0
```

Trying to free `0x20656e69766f4206` on third break, garbage address

Further analysis:

```
r
b *Convert_ASN1_to_X509_NAME+488
c
scudo chunk $x0
```

Trying to `Delete_OBJECT_IDENTIFIER` that is not allocated.

-> Check dedicated file

```
r
b *Convert_ASN1_to_X509_NAME
c
ni 23
scudo chunk *((void**)($sp+0x28))
ni 60
```


### BT7

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.skt.smartbill/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.skt.smartbill memory reproduced_crashes/bt_7/output_R58N349AKNY_17:46-06-03-2023_default_id:000006,sig:06,src:000121,time:2497,execs:1756,op:havoc,rep:4 0 0
```

#### gdb commands

```
r
b *Delete_ASN1_STRING+56
c
scudo chunk $x0
c
scudo chunk $x0
c
scudo chunk $x0
c
scudo chunk $x0
```

On fourth break in `Delete_ASN1_STRING` chunk is not allocated.

Same error as BT5, getting out of the loop and trying to free again.


### BT13

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.skt.smartbill/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.skt.smartbill memory reproduced_crashes/bt_13/output_R58N349AKNY_17:46-06-03-2023_default_id:000023,sig:06,src:000121,time:14543,execs:3464,op:havoc,rep:4 0 0
```

#### gdb commands

```
r
b *Convert_ASN1_to_X509_TBS_CERT+268
c
si
scudo chunk *((void**)($sp+0x10))
si
```

frees unallocated chunk, on `$sp+0x10` after `Get_DER_Child`, `$sp-0x40` at `Convert_ASN1_to_X509_TBS_CERT+268`.

-> Check dedicated file



# kr.go.nts.android

## `Java_com_dreamsecurity_dstoolkit_cert_X509Certificate__1getSubjectAltName_1IdentifyData_1RealName@0-0`

```
python3 fuzzing/triage.py --target kr.go.nts.android --target_function Java_com_dreamsecurity_dstoolkit_cert_X509Certificate__1getSubjectAltName_1IdentifyData_1RealName@0-0 --debug --device RF8N12BM5VN
```

### BT3

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/kr.go.nts.android/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov kr.go.nts.android memory reproduced_crashes/bt_3/output_R58N115Q1DB_21:34-06-01-2023_Master_id:000007,sig:06,src:000677,time:170138839,execs:36129714,op:havoc,rep:4 0 0
```

#### gdb commands

```
r
b *_ZN15ASN1OctetString12extractValueEv+348
c

```

Not too sure what causes the crash, segfault on memory access but what exactly?



# heartratemonitor.heartrate.pulse.pulseapp

## `Java_com_google_android_decode_AoeUtils_ae@0-0`

```
python3 fuzzing/triage.py --target heartratemonitor.heartrate.pulse.pulseapp --target_function Java_com_google_android_decode_AoeUtils_ae@0-0 --debug --device RF8N12BM5VN
```

### BT1

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/heartratemonitor.heartrate.pulse.pulseapp/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov heartratemonitor.heartrate.pulse.pulseapp memory reproduced_crashes/bt_1/output_R58N349AKNY_13:47-12-01-2023_default_id:000009,sig:06,src:000120+000178,time:60424,execs:26488,op:splice,rep:4 0 0
```

#### gdb commands

```
r
b *sub70+184
b *ll11lll11l+2440

c
scudo chunk $x21

define csi
ni
scudo chunk #$x21
end

c

csi

b *sub70+476
c
```

Checksum of chunk to be freed is 0. -> Check dedicated file




# com.tplink.skylight

Missing from androlib

## `Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo@2-0`

```
python3 fuzzing/triage.py --target com.tplink.skylight --target_function Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo@2-0 --debug --device RF8N12BM5VN
```

### BT0

```

```

#### gdb commands

```
r
c
```




# com.hyundaicard.cultureapp

## `Java_com_nshc_NSaferJNI_N_1PublicKeyExport@0-0`

```
python3 fuzzing/triage.py --target com.hyundaicard.cultureapp --target_function Java_com_nshc_NSaferJNI_N_1PublicKeyExport@0-0 --debug --device RF8N12BM5VN
```

### BT0

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.hyundaicard.cultureapp/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.hyundaicard.cultureapp memory reproduced_crashes/bt_0/output_R58N349AKNY_22:47-10-01-2023_default_id:000000,sig:11,src:000138+000032,time:92446,execs:42073,op:splice,rep:16 0 0
```

#### gdb commands

```
r
b *NI_PublicKeyDecode+240
c
scudo chunk $x0
scudo chunk $x1
```

Trying to copy `0x2e1` bytes of data to garbage address `0x7fedb05e50`

-> Check dedicated file


# com.samsung.android.samsungpay.gear

## `Java_com_fourthline_nfc_internal_NfcImageConverterInternal_decodeJP2ByteArray@0-0`

```
python3 fuzzing/triage.py --target com.samsung.android.samsungpay.gear --target_function Java_com_fourthline_nfc_internal_NfcImageConverterInternal_decodeJP2ByteArray@0-0 --debug --device RF8N12BM5VN
```

### BT0

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.samsung.android.samsungpay.gear/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.samsung.android.samsungpay.gear memory reproduced_crashes/bt_0/output_R58MA2XTBEB_15:50-13-01-2023_Slave_2_id:000000,sig:11,src:010305,time:51487711,execs:4483066,op:havoc,rep:2 0 0
```

#### gdb commands

```
r
c
```

Scudo related? not sure
-> doesn't finish to upload



# com.ahnlab.v3mobileplus

## `Java_com_lumensoft_ks_KSNative_GpkiBriefSign@0`

```
python3 fuzzing/triage.py --target com.ahnlab.v3mobileplus --target_function Java_com_lumensoft_ks_KSNative_GpkiBriefSign@0 --debug --device RF8N12BM5VN
```

### BT1

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.ahnlab.v3mobileplus/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.ahnlab.v3mobileplus memory reproduced_crashes/bt_1/output_RF8N12BM5VN_02:32-18-02-2023_default_id:000005,sig:06,src:000121,time:7480,execs:4802,op:havoc,rep:2 0 0
```

#### gdb commands

```
r
b *BIN_Free+28
c
c
c
scudo chunk $x0
```

Trying to free already available/freed chunk

-> Check dedicated file


# com.kbankwith.smartbank

## `Java_com_ubikey_jni_UbikeyJni_jGetOrg@0-0`

```
python3 fuzzing/triage.py --target com.kbankwith.smartbank --target_function Java_com_ubikey_jni_UbikeyJni_jGetOrg@0-0 --debug --device RF8N12BM5VN
```

### BT2

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.kbankwith.smartbank/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.kbankwith.smartbank memory reproduced_crashes/bt_2/output_R58MA2XTBEB_01:49-19-01-2023_default_id:000017,sig:11,src:000121,time:7912,execs:1986,op:havoc,rep:4 0 0
```

#### gdb commands

```
r
b *Convert_ASN1_to_X509_NAME+88
c
scudo chunk $x0
```

Trying to delete already free string/chunk.

Looks like same crash as first one in `Convert_ASN1_to_X509_NAME`.



## `Java_com_ubikey_jni_UbikeyJni_jGetOrgName@0-0`

```
python3 fuzzing/triage.py --target com.kbankwith.smartbank --target_function Java_com_ubikey_jni_UbikeyJni_jGetOrgName@0-0 --debug --device RF8N12BM5VN
```

### BT9

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.kbankwith.smartbank/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.kbankwith.smartbank memory reproduced_crashes/bt_9/output_R58MA2XTBEB_02:02-19-01-2023_default_id:000013,sig:11,src:000121,time:7665,execs:1702,op:havoc,rep:8 0 0
```

Crashes the whole device

Looks like same crash as first one in `Convert_ASN1_to_X509_NAME`.

#### gdb commands

```
r
c
```


## `Java_com_ubikey_jni_UbikeyJni_jCertInfo@0-0`

```
python3 fuzzing/triage.py --target com.kbankwith.smartbank --target_function Java_com_ubikey_jni_UbikeyJni_jCertInfo@0-0 --debug --device RF8N12BM5VN
```

### BT6

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.kbankwith.smartbank/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.kbankwith.smartbank memory reproduced_crashes/bt_6/output_R58MA2XTCLE_00:56-13-01-2023_default_id:000024,sig:11,src:000121,time:190206,execs:37683,op:havoc,rep:2 0 0
```

#### gdb commands

```
r
c
scudo chunk $x9
```

Trying to load from not allocated chunk



## `Java_com_ubikey_jni_UbikeyJni_jGetPolicyOID@0-`

```
python3 fuzzing/triage.py --target com.kbankwith.smartbank --target_function Java_com_ubikey_jni_UbikeyJni_jGetPolicyOID@0-0 --debug --device RF8N12BM5VN
```

### BT3

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.kbankwith.smartbank/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.kbankwith.smartbank memory reproduced_crashes/bt_3/output_R58MA2XTBEB_02:10-19-01-2023_default_id:000023,sig:11,src:000121,time:6676,execs:2956,op:havoc,rep:8 0 0
```

#### gdb commands

```
r
b *Clear_OBJECT_IDENTIFIER+28
c
c
c
scudo chunk $x0
```

Trying to free garbage address `0x20656e69766f4206`.

Looks like same crash as first one in `Convert_ASN1_to_X509_NAME`.



### BT12

Crashes device

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.kbankwith.smartbank/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.kbankwith.smartbank memory reproduced_crashes/bt_12/output_R58MA2XTBEB_02:10-19-01-2023_default_id:000019,sig:11,src:000121,time:4853,execs:2421,op:havoc,rep:4 0 0
```

#### gdb commands

```
r
c
```
