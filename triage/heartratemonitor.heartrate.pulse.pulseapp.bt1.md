# Detailed instructions

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

Checksum of chunk to be freed is 0.


## Decompiled offending function `ll11lll11l`

```c
long ll11lll11l(long param_1,int param_2)

{
  int iVar1;
  long lVar2;
  ulong *puVar3;
  void *__ptr;
  void *__ptr_00;
  void *__ptr_01;
  uint uVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  byte *pbVar8;
  ulong *puVar9;
  byte *pbVar10;
  ulong *puVar11;
  ulong uVar12;
  ulong uVar13;
  ulong uVar14;
  ulong uVar15;
  int local_134;
  ulong local_130;
  int local_128 [50];
  
  lVar2 = tpidr_el0;
  lVar5 = *(long *)(lVar2 + 0x28);
  __ptr = (void *)FUN_0010a6b0();
  __ptr_00 = (void *)lilllilili(&DAT_001135f2,0x17,&local_130);
  __ptr_01 = malloc(local_130 + 1);
  local_128[0] = 2;
  do {
    iVar1 = local_128[0] + 5;
    local_128[0] = local_128[0] + 6;
  } while (iVar1 < 7);
  local_128[0] = 2;
  do {
    iVar1 = local_128[0] + 3;
    local_128[0] = local_128[0] + 4;
  } while (iVar1 < 5);
  if (local_128[0] != 0) {
    local_128[0] = 2;
    do {
      iVar1 = local_128[0] + 5;
      local_128[0] = local_128[0] + 6;
    } while (iVar1 < 7);
  }
  local_128[0] = 2;
  do {
    iVar1 = local_128[0] + 5;
    local_128[0] = local_128[0] + 6;
  } while (iVar1 < 7);
  if (local_128[0] != 0) {
    local_128[0] = 2;
    do {
      iVar1 = local_128[0] + 1;
      local_128[0] = local_128[0] + 2;
    } while (iVar1 < 3);
  }
  local_134 = 0x4b;
  local_128[0] = 2;
  do {
    iVar1 = 0;
    if (local_128[0] != 0) {
      iVar1 = local_134 / local_128[0];
    }
    local_134 = iVar1 + -1;
    iVar1 = local_128[0] + 1;
    local_128[0] = local_128[0] + 2;
  } while (iVar1 < 3);
  if (local_134 != 0) {
    local_128[0] = 2;
    do {
      iVar1 = local_128[0] + 3;
      local_128[0] = local_128[0] + 4;
    } while (iVar1 < 5);
  }
  local_128[0] = 2;
  do {
    iVar1 = local_128[0] + 3;
    local_128[0] = local_128[0] + 4;
  } while (iVar1 < 5);
  if (local_130 != 0) {
    if ((local_130 < 0x20) ||
       ((__ptr_01 < (void *)((long)__ptr_00 + local_130) &&
        (__ptr_00 < (void *)((long)__ptr_01 + local_130))))) {
      uVar6 = 0;
    }
    else {
      uVar6 = local_130 & 0xffffffffffffffe0;
      puVar9 = (ulong *)((long)__ptr_00 + 0x10);
      puVar11 = (ulong *)((long)__ptr_01 + 0x10);
      uVar12 = uVar6;
      do {
        puVar3 = puVar9 + -1;
        uVar13 = puVar9[-2];
        uVar15 = puVar9[1];
        uVar14 = *puVar9;
        puVar9 = puVar9 + 4;
        uVar12 = uVar12 - 0x20;
        puVar11[-1] = (*puVar3 & 0xff00000000000000 | (ulong)((uint7)*puVar3 ^ 0xdfdfdfdfdfdfdf)) ^
                      0xdf00000000000000;
        puVar11[-2] = (uVar13 & 0xff00000000000000 | (ulong)((uint7)uVar13 ^ 0xdfdfdfdfdfdfdf)) ^
                      0xdf00000000000000;
        puVar11[1] = (uVar15 & 0xff00000000000000 | (ulong)((uint7)uVar15 ^ 0xdfdfdfdfdfdfdf)) ^
                     0xdf00000000000000;
        *puVar11 = (uVar14 & 0xff00000000000000 | (ulong)((uint7)uVar14 ^ 0xdfdfdfdfdfdfdf)) ^
                   0xdf00000000000000;
        puVar11 = puVar11 + 4;
      } while (uVar12 != 0);
      if (local_130 == uVar6) goto LAB_0010a20c;
    }
    lVar7 = local_130 - uVar6;
    pbVar8 = (byte *)((long)__ptr_01 + uVar6);
    pbVar10 = (byte *)((long)__ptr_00 + uVar6);
    do {
      lVar7 = lVar7 + -1;
      *pbVar8 = *pbVar10 ^ 0xdf;
      pbVar8 = pbVar8 + 1;
      pbVar10 = pbVar10 + 1;
    } while (lVar7 != 0);
  }
LAB_0010a20c:
  local_128[0] = 0x8b;
  *(undefined *)((long)__ptr_01 + local_130) = 0;
  free(__ptr_00);
  qqppqppq(local_128,__ptr_01,__ptr);
  qqqpqpqp(local_128,param_1,(long)param_2);
  uVar4 = (uint)*(byte *)(param_1 + param_2 + -1);
  iVar1 = 0;
  if (uVar4 < 0x11) {
    iVar1 = param_2 - uVar4;
  }
  if (iVar1 != 0) {
    if (iVar1 < param_2) {
      memset((void *)(param_1 + iVar1),0,(long)(param_2 - iVar1));
    }
    free(__ptr_01);
    free(__ptr);
  }
  if (*(long *)(lVar2 + 0x28) == lVar5) {
    return param_1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

memset sets chunk header to 0. `param_1` is address to a chunk, `param_2` is 0.

The chunk pointed at by `param_1` looks like the following:
```
Chunk(addr=0x7d5dad7e10, size=0x5, state=Allocated, classid=1)
Origin: Malloc
Chunk size: 5 (0x5)
Offset: 0 (0x0)
Checksum: 0xba8a
Allocated
```

However for uVar4, it actually reads out an entire byte from `param_1 + 4 - 1`, which doesn't entirely fit into the chunk size of `param_1`. Therefore `uVar4` is bigger than `param_2`, and the memset acts on the header of the `param_1` chunk.

The data at `param_1 + 4 - 1` is changed by the function `qqqpqpqp` which does some weird byte stuff and gets `param_1` as `param_2` and `param_2` as `param_3`:

```c
void qqqpqpqp(long param_1,long param_2,ulong param_3)

{
  undefined8 *puVar1;
  long lVar2;
  long lVar3;
  ulong uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  
  lVar2 = tpidr_el0;
  lVar3 = *(long *)(lVar2 + 0x28);
  if (param_3 != 0) {
    uVar4 = 0;
    do {
      puVar1 = (undefined8 *)(param_2 + uVar4);
      uVar6 = puVar1[1];
      uVar5 = *puVar1;
      FUN_00101908(puVar1,param_1);
      uVar4 = uVar4 + 0x10;
      *(byte *)puVar1 = *(byte *)puVar1 ^ *(byte *)(param_1 + 0xb0);
      *(byte *)((long)puVar1 + 1) = *(byte *)((long)puVar1 + 1) ^ *(byte *)(param_1 + 0xb1);
      *(byte *)((long)puVar1 + 2) = *(byte *)((long)puVar1 + 2) ^ *(byte *)(param_1 + 0xb2);
      *(byte *)((long)puVar1 + 3) = *(byte *)((long)puVar1 + 3) ^ *(byte *)(param_1 + 0xb3);
      *(byte *)((long)puVar1 + 4) = *(byte *)((long)puVar1 + 4) ^ *(byte *)(param_1 + 0xb4);
      *(byte *)((long)puVar1 + 5) = *(byte *)((long)puVar1 + 5) ^ *(byte *)(param_1 + 0xb5);
      *(byte *)((long)puVar1 + 6) = *(byte *)((long)puVar1 + 6) ^ *(byte *)(param_1 + 0xb6);
      *(byte *)((long)puVar1 + 7) = *(byte *)((long)puVar1 + 7) ^ *(byte *)(param_1 + 0xb7);
      *(byte *)(puVar1 + 1) = *(byte *)(puVar1 + 1) ^ *(byte *)(param_1 + 0xb8);
      *(byte *)((long)puVar1 + 9) = *(byte *)((long)puVar1 + 9) ^ *(byte *)(param_1 + 0xb9);
      *(byte *)((long)puVar1 + 10) = *(byte *)((long)puVar1 + 10) ^ *(byte *)(param_1 + 0xba);
      *(byte *)((long)puVar1 + 0xb) = *(byte *)((long)puVar1 + 0xb) ^ *(byte *)(param_1 + 0xbb);
      *(byte *)((long)puVar1 + 0xc) = *(byte *)((long)puVar1 + 0xc) ^ *(byte *)(param_1 + 0xbc);
      *(byte *)((long)puVar1 + 0xd) = *(byte *)((long)puVar1 + 0xd) ^ *(byte *)(param_1 + 0xbd);
      *(byte *)((long)puVar1 + 0xe) = *(byte *)((long)puVar1 + 0xe) ^ *(byte *)(param_1 + 0xbe);
      *(byte *)((long)puVar1 + 0xf) = *(byte *)((long)puVar1 + 0xf) ^ *(byte *)(param_1 + 0xbf);
      *(undefined8 *)(param_1 + 0xb8) = uVar6;
      *(undefined8 *)(param_1 + 0xb0) = uVar5;
    } while (uVar4 < param_3);
  }
  if (*(long *)(lVar2 + 0x28) == lVar3) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
