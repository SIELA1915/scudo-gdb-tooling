# Detailed instructions

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

Trying to copy `0x2e1` bytes of data to garbage address `0x7fedb05e50`, in line 44 of `NI_PublicKeyDecode`. Garbage address is caused by `ASN1_length_decode` returning max UINT value.



## Decompiled offending function `NI_PublicKeyDecode`

```c
undefined4
NI_PublicKeyDecode(void *param_1,uint param_2,void *param_3,uint *param_4,void *param_5,
                  uint *param_6)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  char *__dest;
  char *__dest_00;
  ulong uVar4;
  undefined4 uVar5;
  char *pcVar6;
  ulong uVar7;
  char *pcVar8;
  uint local_94;
  undefined auStack_90 [20];
  undefined auStack_7c [20];
  long local_68;
  
  lVar2 = tpidr_el0;
  local_68 = *(long *)(lVar2 + 0x28);
  uVar1 = param_2 + 0x80;
  __dest = (char *)calloc(1,(ulong)uVar1);
  __dest_00 = (char *)calloc(1,(ulong)uVar1);
  uVar5 = 0x3f8;
  if ((__dest == (char *)0x0) || (__dest_00 == (char *)0x0)) goto joined_r0x001403d8;
  memcpy(__dest,param_1,(ulong)param_2);
  pcVar6 = __dest + 1;
  if (*__dest != '0') {
    uVar5 = 0x3f9;
    goto joined_r0x001403d8;
  }
  uVar4 = ASN1_length_decode(pcVar6,&local_94);
  if (local_94 <= uVar1) {
    memcpy(__dest_00,pcVar6 + (uVar4 & 0xffffffff),(ulong)local_94);
    pcVar8 = __dest_00 + 1;
    if (*__dest_00 == '0') {
      uVar4 = ASN1_length_decode(pcVar8,&local_94);
      uVar7 = (ulong)local_94;
      if (local_94 <= uVar1) {
        pcVar8 = pcVar8 + (uVar4 & 0xffffffff);
        memcpy(__dest,pcVar8,uVar7);
        pcVar8 = pcVar8 + uVar7;
        if (*pcVar8 == '\x04') {
          uVar4 = ASN1_length_decode(pcVar8 + 1,&local_94);
          if (local_94 < 0x15) {
            memcpy(auStack_7c,pcVar8 + 1 + (uVar4 & 0xffffffff),(ulong)local_94);
            SHA1_hmac(__dest_00,uVar7,nsg_PukMacKey,0x14,auStack_90);
            iVar3 = memcmp(auStack_7c,auStack_90,0x14);
            if ((iVar3 == 0) && (*__dest == '\x13')) {
              uVar4 = ASN1_length_decode(pcVar6,&local_94);
              uVar1 = local_94;
              uVar7 = (ulong)local_94;
              pcVar6 = pcVar6 + (uVar4 & 0xffffffff);
              if (param_3 != (void *)0x0) {
                if (0x100 < local_94) goto LAB_001403c8;
                memcpy(param_3,pcVar6,uVar7);
                *param_4 = uVar1;
              }
              pcVar6 = pcVar6 + uVar7;
              if (*pcVar6 == '\x04') {
                uVar4 = ASN1_length_decode(pcVar6 + 1,&local_94);
                if (local_94 <= *param_6) {
                  memcpy(param_5,pcVar6 + 1 + (uVar4 & 0xffffffff),(ulong)local_94);
                  uVar5 = 0;
                  *param_6 = local_94;
                  goto joined_r0x001403d8;
                }
              }
            }
          }
        }
      }
    }
  }
LAB_001403c8:
  uVar5 = 0x3f9;
joined_r0x001403d8:
  if (__dest != (char *)0x0) {
    free(__dest);
  }
  if (__dest_00 != (char *)0x0) {
    free(__dest_00);
  }
  if (*(long *)(lVar2 + 0x28) == local_68) {
    return uVar5;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
