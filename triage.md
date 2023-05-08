# TRIAGE LOG

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
python3 fuzzing/triage.py --target com.skt.smartbill --target_function         Java_com_ubikey_jni_UbikeyJni_jGetUser@0 --debug --device RF8N12BM5VN
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

## com.skt.smartbill

`Java_com_ubikey_jni_UbikeyJni_jGetUser@0`

```
python3 fuzzing/triage.py --target com.skt.smartbill --target_function         Java_com_ubikey_jni_UbikeyJni_jGetUser@0 --debug --device RF8N12BM5VN
```

### BT5

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.skt.smartbill/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.skt.smartbill memory reproduced_crashes/bt_5/output_R58MA2XTBEB_18:59-03-03-2023_default_id:000002,sig:11,src:000121,time:7294,execs:1869,op:havoc,rep:2 0 0
```

#### gdb commands

```
r
c
f 5
p $x0
```

freeing 0x0, invalid address



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



### BT13

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.skt.smartbill/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.skt.smartbill memory reproduced_crashes/bt_13/output_R58N349AKNY_17:46-06-03-2023_default_id:000023,sig:06,src:000121,time:14543,execs:3464,op:havoc,rep:4 0 0
```

#### gdb commands

```
r
b *Convert_ASN1_to_X509_TBS_CERT+268
c
si 14
si
finish
```

frees unallocated chunk, on `$sp+0x10` after `Get_DER_Child`, `$sp-0x40` at `Convert_ASN1_to_X509_TBS_CERT+268`.



## kr.go.nts.android

`Java_com_dreamsecurity_dstoolkit_cert_X509Certificate__1getSubjectAltName_1IdentifyData_1RealName@0-0`

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
c
f 1
scudo chunk $x0
scudo chunk $x1
```

copying memory into an unallocated area

