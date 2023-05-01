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

## BT5

```
LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/com.skt.smartbill/lib/arm64-v8a:/system/lib64 gdb -iex 'set auto-load safe-path .' --args ./harness_debug_nocov com.skt.smartbill memory reproduced_crashes/bt_5 0 0
```
