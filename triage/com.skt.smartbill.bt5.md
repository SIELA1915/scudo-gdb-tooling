# Detailed instructions

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


```
r
b *Convert_ASN1_to_X509_NAME
c
ni 23
scudo chunk *((void**)($sp+0x28))
ni 60
```



## Decompiled `Convert_ASN1_to_X509_NAME`

```c
undefined4 Convert_ASN1_to_X509_NAME(long param_1,long *param_2)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 *local_60;
  int local_58;
  long local_50;
  long invalid;
  long local_40;

  local_40 = 0;
  invalid = 0;
  local_50 = 0;
  local_60 = (undefined4 *)0x0;
  if ((param_1 != 0) && (param_2 != (long *)0x0)) {
    if (*param_2 == 0) {
      invalid = Create_X509_NAME();
    }
    else {
      invalid = *param_2;
    }
    iVar1 = Compute_ASN1_ST_ChildNum(param_1);
    if ((iVar1 != 0) && (invalid != 0)) {
      local_58 = 0;
      while( true ) {
        if (iVar1 <= local_58) {
          *param_2 = invalid;
          return 1;
        }
        uVar3 = Get_DER_Child(param_1,local_58,0x11);
        local_40 = Get_DER_Child(uVar3,0,0x10);
        Delete_ASN1(uVar3);
        if (((local_40 == 0) || (local_50 = Get_DER_Child(local_40,0,6), local_50 == 0)) ||
           (local_60 = (undefined4 *)Get_DER_Child(local_40,1,0x20), local_60 == (undefined4 *)0x0))
        break;
        Delete_ASN1(local_40);
        local_40 = 0;
        iVar2 = Add_X509_NAME_child_OID
                          (invalid,local_50,*local_60,*(undefined8 *)(local_60 + 2),local_60[4],
                           0xffffffff);
        if (iVar2 != 1) break;
        Delete_OBJECT_IDENTIFIER(local_50);
        Delete_ASN1_STRING(local_60);
        local_58 = local_58 + 1;
      }
    }
  }
  if (local_50 != 0) {
    Delete_OBJECT_IDENTIFIER(local_50);
  }
  if (invalid != 0) {
    Delete_X509_NAME(invalid);
  }
  if (local_60 != (undefined4 *)0x0) {
    Delete_ASN1_STRING(local_60);
  }
  if (local_40 != 0) {
    Delete_ASN1(local_40);
  }
  return 0;
}
```

while(true) executes twice, end of first loop `local_50` is freed by `Delete_OBJECT_IDENTIFIER`, in second iteration `local_40 == 0`, so the break is called with unchanged `local_50`, and it tries to free `local_50` again with `Delete_OBJECT_IDENTIFIER`.  
-> Double free!
