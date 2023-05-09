# Detailed instructions

## `Java_com_ubikey_jni_UbikeyJni_jGetUser@0`

```
python3 fuzzing/triage.py --target com.skt.smartbill --target_function         Java_com_ubikey_jni_UbikeyJni_jGetUser@0 --debug --device RF8N12BM5VN
```

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
si
scudo chunk *((void**)($sp+0x10))
si
```

frees unallocated chunk, on `$sp+0x10` after `Get_DER_Child`, `$sp-0x40` at `Convert_ASN1_to_X509_TBS_CERT+268`.


## Decompiled offending function `FUN_0015ae44`

```c
undefined4 FUN_0015ae44(undefined8 param_1,long **param_2)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long *local_40;
  
  lVar2 = Get_DER_Child(param_1,4,0x10);
  if (((lVar2 != 0) && (local_40 = (long *)FUN_0016054c(), local_40 != (long *)0x0)) &&
     (iVar1 = Compute_ASN1_ST_ChildNum(lVar2), iVar1 == 2)) {
    lVar3 = Get_DER_Child(lVar2,0,0x17);
    *local_40 = lVar3;
    if (*local_40 != 0) {
      lVar3 = Get_DER_Child(lVar2,1,0x17);
      local_40[1] = lVar3;
      if (local_40[1] != 0) {
        *param_2 = local_40;
        if (lVar2 != 0) {
          Delete_ASN1(lVar2);
        }
        return 1;
      }
    }
  }
  if (local_40 != (long *)0x0) {
    FUN_001599d0(local_40);
  }
  if (lVar2 != 0) {
    Delete_ASN1(lVar2);
  }
  return 0;
}
```

lVar2 is null, `local_40` is not initialized to 0, so `FUN_001599d0` is executed, which tries to free local_40.
