# Detailed instructions

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

Trying to free already available/freed chunk. Chunk is freed in line 41, then jumps to line 54 and in line 56 the first conditions are false, so the chunk isn't recreated, and then it tries to be freed again.



## Decompiled offending function `KS_BIN_To_TBSCertificate`

```c
long * KS_BIN_To_TBSCertificate(int *param_1)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  long lVar4;
  long lVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  char *pcVar8;
  byte bVar9;
  int local_60;
  int local_5c;
  long local_58;
  
  lVar2 = ___stack_chk_guard;
  local_58 = ___stack_chk_guard;
  if (((param_1 != (int *)0x0) && (*param_1 != 0)) &&
     (plVar3 = (long *)malloc(0x50), plVar3 != (long *)0x0)) {
    ks_memset(plVar3,0,0x50);
    pcVar8 = *(char **)(param_1 + 2);
    iVar1 = *param_1;
    local_60 = 1;
    if (*pcVar8 == -0x60) {
      asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
      if ((-1 < local_5c) && (local_60 + local_5c <= iVar1)) {
        local_60 = local_60 + 1;
        asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
        if ((-1 < local_5c) &&
           ((local_60 + local_5c <= iVar1 &&
            (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 != 0)))) {
          bVar9 = pcVar8[local_60];
          local_60 = local_5c + local_60;
          lVar5 = KS_BIN_To_INTEGER(lVar4);
          *plVar3 = lVar5;
          if (lVar5 != 0) {
            BIN_Free(lVar4);
            local_60 = local_60 + 1;
            goto LAB_0013cc24;
          }
          goto LAB_0013cf94;
        }
      }
LAB_0013cf90:
      lVar4 = 0;
    }
    else {
      lVar4 = 0;
      bVar9 = 0;
LAB_0013cc24:
      asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
      if ((-1 < local_5c) && (local_60 + local_5c <= iVar1)) {
        lVar4 = BIN_New(local_5c,pcVar8 + local_60);
        if (lVar4 == 0) goto LAB_0013cf90;
        local_60 = local_60 + local_5c;
        lVar5 = KS_BIN_To_INTEGER(lVar4);
        plVar3[1] = lVar5;
        if (lVar5 != 0) {
          BIN_Free(lVar4);
          local_60 = local_60 + 1;
          asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
          if (((local_5c < 0) || (iVar1 < local_60 + local_5c)) ||
             (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 == 0)) goto LAB_0013cf90;
          local_60 = local_60 + local_5c;
          lVar5 = KS_BIN_To_AlgorithmIdentifier(lVar4);
          plVar3[2] = lVar5;
          if (lVar5 != 0) {
            BIN_Free(lVar4);
            local_60 = local_60 + 1;
            asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
            if (((local_5c < 0) || (iVar1 < local_60 + local_5c)) ||
               (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 == 0)) goto LAB_0013cf90;
            local_60 = local_60 + local_5c;
            puVar6 = (undefined8 *)malloc(0x10);
            ks_memset(puVar6,0,0x10);
            uVar7 = BIN_Copy(lVar4);
            *puVar6 = uVar7;
            uVar7 = KS_BIN_To_RDNSequence(lVar4);
            puVar6[1] = uVar7;
            plVar3[3] = (long)puVar6;
            if (puVar6 != (undefined8 *)0x0) {
              BIN_Free(lVar4);
              local_60 = local_60 + 1;
              asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
              if (((local_5c < 0) || (iVar1 < local_60 + local_5c)) ||
                 (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 == 0)) goto LAB_0013cf90;
              local_60 = local_60 + local_5c;
              lVar5 = KS_BIN_To_Validity(lVar4);
              plVar3[4] = lVar5;
              if (lVar5 != 0) {
                BIN_Free(lVar4);
                local_60 = local_60 + 1;
                asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
                if (((local_5c < 0) || (iVar1 < local_60 + local_5c)) ||
                   (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 == 0)) goto LAB_0013cf90;
                local_60 = local_60 + local_5c;
                puVar6 = (undefined8 *)malloc(0x10);
                ks_memset(puVar6,0,0x10);
                uVar7 = BIN_Copy(lVar4);
                *puVar6 = uVar7;
                uVar7 = KS_BIN_To_RDNSequence(lVar4);
                puVar6[1] = uVar7;
                plVar3[5] = (long)puVar6;
                if (puVar6 != (undefined8 *)0x0) {
                  BIN_Free(lVar4);
                  local_60 = local_60 + 1;
                  asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
                  if (((local_5c < 0) || (iVar1 < local_60 + local_5c)) ||
                     (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 == 0)) goto LAB_0013cf90;
                  local_60 = local_60 + local_5c;
                  lVar5 = KS_BIN_To_SubjectPublicKeyInfo(lVar4);
                  plVar3[6] = lVar5;
                  if (lVar5 != 0) {
                    BIN_Free(lVar4);
                    if (*param_1 <= local_60) {
                      plVar3[9] = 0;
                      goto LAB_0013cfa8;
                    }
                    if (bVar9 < 2) goto LAB_0013cfa8;
                    local_60 = local_60 + 1;
                    plVar3[7] = 0;
                    plVar3[8] = 0;
                    asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
                    lVar4 = 0;
                    if (-1 < local_5c) {
                      if (local_60 + local_5c <= iVar1) {
                        local_60 = local_60 + 1;
                        asn1_x509_length_decode(pcVar8,&local_60,&local_5c);
                        if (((-1 < local_5c) && (local_60 + local_5c <= iVar1)) &&
                           (lVar4 = BIN_New(local_5c,pcVar8 + local_60), lVar4 != 0)) {
                          local_60 = local_60 + local_5c;
                          lVar5 = KS_BIN_To_Extensions(lVar4);
                          plVar3[9] = lVar5;
                          if (lVar5 != 0) {
                            BIN_Free(lVar4);
                            goto LAB_0013cfa8;
                          }
                          goto LAB_0013cf94;
                        }
                      }
                      goto LAB_0013cf90;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
LAB_0013cf94:
    KS_TBSCertificate_Free(plVar3);
    BIN_Free(lVar4);
  }
  plVar3 = (long *)0x0;
LAB_0013cfa8:
  if (lVar2 == local_58) {
    return plVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
