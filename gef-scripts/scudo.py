import ctypes
import gdb
import enum
import math

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

SCUDO_REGION_INFO_ARRAY_DEFAULT_NAME = "RegionInfoArray"
SCUDO_CACHE_LINE_SIZE = 64
    
class Config(metaclass=Singleton):
    max_num_cached_hint = -1
    num_classes = -1
    max_size = -1
    largest_class_id = -1
    batch_class_id = -1
    class_size_list = []
    min_alignment = 1 << 4
    primary_compact_ptr_scale = 0
    compact_pointer = ctypes.c_uint64

    def __init__(self):
        min_alignment = (4 if gef and gef.arch.ptrsize == 8 else 3)
        compact_pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        try:
            gdb.parse_and_eval(f"scudo::DefaultConfig")
        except gdb.error as e:
            if "Cannot look up value of a typedef" in str(e):
                min_size_log = 5
                mid_size_log = 8
                max_size_log = 17
                num_bits = 3
                self.max_num_cached_hint = 14
                max_bytes_cached_log = 10
                size_delta = 0
                mid_class = int((1 << mid_size_log) / (1 << min_size_log))
            
                S = num_bits - 1
                M = (1 << S) - 1
                self.max_size = (1 << max_size_log) + size_delta
                self.num_classes = mid_class + ((max_size_log - mid_size_log) << S) + 1
                self.largest_class_id = self.num_classes - 1
                self.batch_class_id = 0

                for i in range(self.num_classes):
                    if i == 0:
                        self.class_size_list += [-1]
                        continue
                    if i <= mid_class:
                        self.class_size_list += [(i << min_size_log) + size_delta]
                        continue

                    cid = i - mid_class
                    T = (1 << mid_size_log) << (cid >> S)

                    self.class_size_list += [T + (T >> S) * (cid & M) + size_delta]

            else:
                try:
                    gdb.parse_and_eval(f"scudo::AndroidConfig")
                except gdb.error as e:
                    if "Cannot look up value of a typedef" in str(e):
                        min_size_log = 4
                        mid_size_log = 6
                        max_size_log = 16
                        num_bits = 7
                        self.max_num_cached_hint = 13
                        max_bytes_cached_log = 13
                        size_delta = 16
                        
                        self.class_size_list = [-1, 0x00020, 0x00030, 0x00040, 0x00050,
                                           0x00060, 0x00070, 0x00090, 0x000b0, 0x000c0,
                                           0x000e0, 0x00120, 0x00160, 0x001c0, 0x00250,
                                           0x00320, 0x00450, 0x00670, 0x00830, 0x00a10,
                                           0x00c30, 0x01010, 0x01210, 0x01bd0, 0x02210,
                                           0x02d90, 0x03790, 0x04010, 0x04810, 0x05a10,
                                           0x07310, 0x08210, 0x10010,]
                        
                        self.num_classes = len(self.class_size_list) - 1
                        self.largest_class_id = self.num_classes - 1
                        self.batch_class_id = 0
                        self.max_size = self.class_size_list[-1]
                        self.compact_pointer = ctypes.c_uint32
                        if gef and gef.arch.ptrsize == 8:
                            self.primary_compact_ptr_scale = self.min_alignment


def decompact_pointer(class_id, compact_ptr) -> int:
    region_info = ScudoRegionInfo(f"{search_for_scudo_regtion_info()}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*class_id}")

    config = Config()

    return region_info.region_beg + (compact_ptr << config.primary_compact_ptr_scale)

                        
class ScudoChunk:
    """Scudo chunk class. The default behavior (from_base=False) is to interpret the data starting at the memory
    address pointed to as the chunk data. Setting from_base to True instead treats that data as the chunk header.
    Ref:  https://un1fuzz.github.io/articles, https://llvm.org/docs/ScudoHardenedAllocator.html"""

    class ChunkState(enum.Enum):
        Available = 0
        Allocated = 1
        Quarantined = 2

        def __str__(self) -> str:
            if (self == self.Available):
                return Color.greenify("Available")
            if (self == self.Allocated):
                return Color.yellowify("Allocated")
            if (self == self.Quarantined):
                return Color.redify("Quarantined")
            return f"Invalid Chunk state: {self.value}"

    class ChunkOrigin(enum.Enum):
        Malloc = 0
        New = 1
        NewArray = 2
        Memalign = 3

        def __str__(self) -> str:
            return self.name

    @staticmethod
    def malloc_chunk_t() -> Type[ctypes.Structure]:
        sizetype = ctypes.c_uint32
        pointertype = ctypes.c_uint16
        class malloc_chunk_cls(ctypes.Structure):
            pass

        malloc_chunk_cls._fields_ = [
            ("size", sizetype),
            ("offset", pointertype),
            ("checksum", pointertype),
        ]
        return malloc_chunk_cls

    def __init__(self, addr: int, from_base: bool = False, allow_unaligned: bool = True) -> None:
        ptrsize = gef.arch.ptrsize
        hdrsize = 16
        self.data_address = addr + hdrsize if from_base else addr
        self.base_address = addr if from_base else addr - hdrsize
#        if not allow_unaligned:
#            self.data_address = gef.heap.malloc_align_address(self.data_address)
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoChunk.malloc_chunk_t())
        self._data = gef.memory.read(
            self.base_address, ctypes.sizeof(ScudoChunk.malloc_chunk_t()))
        self._chunk = ScudoChunk.malloc_chunk_t().from_buffer_copy(self._data)
        return

    @property
    def size(self) -> int:
        return (self._chunk.size >> 12)

    @property
    def offset(self) -> int:
        return self._chunk.offset

    @property
    def checksum(self) -> int:
        return self._chunk.checksum

    @property
    def state(self) -> ChunkState:
        return ScudoChunk.ChunkState((self._chunk.size >> 8) & 0x3)

    @property
    def origin(self) -> ChunkOrigin:
        return ScudoChunk.ChunkOrigin((self._chunk.size >> 10) & 0x3)

    @property
    def classid(self) -> int:
        return self._chunk.size & 0xf

    @property
    def was_zeroed(self) -> bool:
        return self.origin and self.state != ScudoChunk.ChunkState.Allocated

    def __str_extended(self) -> str:
        msg = []
        failed = False

        try:
            if self.state == ScudoChunk.ChunkState.Available:
                msg.append("Was zeroed: {0!r}".format(self.origin == ScudoChunk.ChunkOrigin.Malloc))
            else:
                msg.append("Origin: {0!s}".format(self.origin))
            msg.append("Chunk size: {0:d} ({0:#x})".format(self.size))
            msg.append("Offset: {0:d} ({0:#x})".format(self.offset))
            msg.append("Checksum: {0:#x}".format(self.checksum))
            failed = True
        except gdb.MemoryError:
            msg.append(f"Chunk size: Cannot read at {self.size_addr:#x} (corrupted?)")

        if failed:
            msg.append(str(self.state))

        return "\n".join(msg)

    def __str__(self) -> str:
        return (f"{Color.colorify('Chunk', 'yellow bold underline')}(addr={self.data_address:#x}, "
                f"size={self.size:#x}, state={self.state!s}, classid={self.classid})")

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"
    
@lru_cache()
def search_for_scudo_region_info() -> int:
    """A helper function to find the scudo `RegionInfoArray` address, either from symbol or from its offset
    from `Allocator`."""
    try:
        addr = parse_address(f"&{SCUDO_REGION_INFO_ARRAY_DEFAULT_NAME}")

    except gdb.error:
        allocator_addr = parse_address("(void *)&Allocator")

        addr = allocator_addr + 192
        
    return addr

@lru_cache()
def search_for_scudo_per_class_array() -> int:
    """A helper function to find the scudo `PerClassArray` address, either from `Allocator`."""

    addr = parse_address("(void *)&(Allocator.TSDRegistry.ThreadTSD.Cache.PerClassArray)")
        
    return addr


class ScudoRegionInfo:
    """Scudo region info class"""

    @staticmethod
    def region_info_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        fields = [
            ("mutex", ctypes.c_uint32),
            ("freelist_size", pointer),
            ("freelist_first", pointer),
            ("freelist_last", pointer),
            ("region_beg", pointer),
            ("popped_blocks", pointer),
            ("pushed_blocks", pointer),
            ("rand_state", ctypes.c_uint32),
            ("mapped_user", pointer),
            ("allocated_user", pointer),
            ("data", ctypes.c_uint8),
            ("release_last_pushed_blocks", pointer),
            ("release_ranges", pointer),
            ("release_last_bytes", pointer),
            ("release_last_at_ns", ctypes.c_uint64),
            ("exhausted", ctypes.c_uint8),
        ]

        class unpadded_region_info_cls(ctypes.Structure):
            _fields_ = fields

        fields += [("padding", (SCUDO_CACHE_LINE_SIZE - (ctypes.sizeof(unpadded_region_info_cls) % SCUDO_CACHE_LINE_SIZE)) * ctypes.c_char)]
        
        class region_info_cls(ctypes.Structure):
            _fields_ = fields
        return region_info_cls

    def __init__(self, addr: str) -> None:
        try:
            self.__address : int = parse_address(f"{addr}")
        except gdb.error:
            self.__address : int = search_for_scudo_region_info()
            # if `search_for_scudo_region_info` throws `gdb.error` on symbol lookup:
            # it means the session is not started, so just propagate the exception
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoRegionInfo.region_info_t())
        self._data = gef.memory.read(self.__address, ctypes.sizeof(ScudoRegionInfo.region_info_t()))
        self.__region = ScudoRegionInfo.region_info_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def num_free(self) -> int:
        return self.__region.freelist_size

    @property
    def first_free(self) -> int:
        return self.__region.freelist_first

    @property
    def last_free(self) -> int:
        return self.__region.freelist_last

    @property
    def region_beg(self) -> int:
        return self.__region.region_beg
    
    @property
    def popped_blocks(self) -> int:
        return self.__region.popped_blocks

    @property
    def pushed_blocks(self) -> int:
        return self.__region.pushed_blocks

    @property
    def rand_state(self) -> int:
        return self.__region.rand_state

    @property
    def mapped_user(self) -> int:
        return self.__region.mapped_user

    @property
    def allocated_user(self) -> int:
        return self.__region.allocated_user

    @property
    def pushed_blocks_at_last_release(self) -> int:
        return self.__region.release_last_pushed_blocks

    @property
    def ranges_released(self) -> int:
        return self.__region.release_ranges

    @property
    def last_released_bytes(self) -> int:
        return self.__region.release_last_bytes

    @property
    def last_release_at_ns(self) -> int:
        return self.__region.release_last_at_ns

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, region_begin={self.region_beg:#x}, " \
                f"mapped={self.mapped_user:#x}, allocated={self.allocated_user:#x}, " \
                f"num_batches={self.num_free:d}"
        return (f"{Color.colorify('Region', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"ScudoRegionInfo(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []
        failed = False

        msg.append("Free list:")
        msg.append("\tNumber free: {0:d}".format(self.num_free))
        msg.append("\tFirst free: {0:#x}".format(self.first_free))
        msg.append("\tLast free: {0:#x}".format(self.last_free))

        msg.append("\nRegion stats:")
        msg.append("\tPopped blocks: {0:d}".format(self.popped_blocks))
        msg.append("\tPushed blocks: {0:d}".format(self.pushed_blocks))

        msg.append("\nRandom state: {0:d}".format(self.rand_state))

        msg.append("\nRelease to OS:")
        msg.append("\tPushed blocks at last release: {0:#x}".format(self.pushed_blocks_at_last_release))
        msg.append("\tRanges released: {0:#x}".format(self.ranges_released))
        msg.append("\tLast released bytes: {0:#x}".format(self.last_released_bytes))
        msg.append("\tLast release at ns: {0:d}".format(self.last_release_at_ns))

        return "\n".join(msg)


        
    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"


class ScudoBatchGroup:
    """Scudo batch group class"""

    @staticmethod
    def batch_group_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        fields = [
            ("next", pointer),
            ("compact_ptr_group_base", pointer),
            ("max_cached_per_batch", ctypes.c_uint16),
            ("pushed_blocks", pointer),
            ("pushed_blocks_at_last_checkpoint", pointer),
            ("batches_size", pointer),
            ("batches_first", pointer),
            ("batches_last", pointer),
        ]

        class batch_group_cls(ctypes.Structure):
            _fields_ = fields
        return batch_group_cls

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoBatchGroup.batch_group_t())
        self._data = gef.memory.read(self.__address, ctypes.sizeof(ScudoBatchGroup.batch_group_t()))
        self.__batch_group = ScudoBatchGroup.batch_group_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def num_batches(self) -> int:
        return self.__batch_group.batches_size

    @property
    def first_batch(self) -> int:
        return self.__batch_group.batches_first

    @property
    def last_batch(self) -> int:
        return self.__batch_group.batches_last

    @property
    def compact_ptr_group_base(self) -> int:
        return self.__batch_group.compact_ptr_group_base
    
    @property
    def max_cached_per_batch(self) -> int:
        return self.__batch_group.max_cached_per_batch

    @property
    def pushed_blocks(self) -> int:
        return self.__batch_group.pushed_blocks

    @property
    def pushed_blocks_at_last_checkpoint(self) -> int:
        return self.__batch_group.pushed_blocks_at_last_checkpoint

    @property
    def next_addr(self) -> int:
        return self.__batch_group.next

    def get_next_batch_group(self) -> "ScudoBatchGroup":
        addr = self.next_addr
        return ScudoBatchGroup(addr)

    def __iter__(self) -> Generator["ScudoBatchGroup", None, None]:
        current_group = self

        while current_group.next_addr:
            yield current_group

            next_group_addr = current_group.next_addr()

            if not Address(value=next_group_addr).valid:
                break

            next_group = current_group.get_next_batch_group()
            if next_group is None:
                break
            current_group = next_group
        return

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, num_batches={self.num_batches:d}, " \
                f"first_batch={self.first_batch:#x}, pushed_blocks={self.pushed_blocks:d}"
        return (f"{Color.colorify('BatchGroup', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"BatchGroup(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Next batch group: {0:#x}".format(self.next_addr))
        msg.append("Compact base addr: {0:#x}".format(self.compact_ptr_group_base))

        msg.append("Max cached per batch: {0:d}".format(self.max_cached_per_batch))

        msg.append("Pushed blocks: {0:d}".format(self.pushed_blocks))
        msg.append("Pushed blocks at last checkpoint: {0:d}".format(self.pushed_blocks_at_last_checkpoint))

        msg.append("Batches:")
        msg.append("\tNumber batches: {0:d}".format(self.num_batches))
        msg.append("\tFirst batch: {0:#x}".format(self.first_batch))
        msg.append("\tLast last: {0:#x}".format(self.last_batch))

        return "\n".join(msg)

        
    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

class ScudoTransferBatch:
    """Scudo transfer batch class"""

    @staticmethod
    def transfer_batch_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        config = Config()
        fields = [
            ("next", pointer),
            ("batches", config.max_num_cached_hint*config.compact_pointer),
            ("count", ctypes.c_uint16),
        ]

        class transfer_batch_cls(ctypes.Structure):
            _fields_ = fields
        return transfer_batch_cls

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoTransferBatch.transfer_batch_t())
        self._data = gef.memory.read(self.__address, ctypes.sizeof(ScudoTransferBatch.transfer_batch_t()))
        self.__transfer_batch = ScudoTransferBatch.transfer_batch_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def count(self) -> int:
        return self.__transfer_batch.count

    @property
    def batches(self) -> [int]:
        return self.__transfer_batch.batches

    @property
    def next_addr(self) -> int:
        return self.__transfer_batch.next

    def get_next_transfer_batch(self) -> "ScudoTransferBatch":
        addr = self.next_addr
        return ScudoTransferBatch(addr)

    def __iter__(self) -> Generator["ScudoTransferBatch", None, None]:
        current_tb = self

        while current_tb.next_addr:
            yield current_tb

            next_tb_addr = current_tb.next_addr()

            if not Address(value=next_tb_addr).valid:
                break

            next_tb= current_tb.get_next_transfer_batch()
            if next_tb is None:
                break
            current_tb = next_tb
        return

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, num_batches={self.count:d}"
        return (f"{Color.colorify('TransferBatch', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"TransferBatch(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Next transfer batch: {0:#x}".format(self.next_addr))
        msg.append("Number batches: {0:d}".format(self.count))

        for _i in range(self.count):
            msg.append("\tBatch #{0:d}: {1:#x}".format(_i, self.batches[_i]))

        return "\n".join(msg)

        
    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

class ScudoPerClass:
    """Scudo per class cache"""

    @staticmethod
    def per_class_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        config = Config()
        fields = [
            ("count", ctypes.c_uint16),
            ("max_count", ctypes.c_uint16),
            ("class_size", pointer),
            ("chunks", config.max_num_cached_hint*config.compact_pointer),
        ]

        class per_class_cls(ctypes.Structure):
            _fields_ = fields
        return per_class_cls

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoPerClass.per_class_t())
        self._data = gef.memory.read(self.__address, ctypes.sizeof(ScudoPerClass.per_class_t()))
        self.__per_class = ScudoPerClass.per_class_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def count(self) -> int:
        return self.__per_class.count
    
    @property
    def max_count(self) -> int:
        return self.__per_class.max_count

    @property
    def class_size(self) -> int:
        return self.__per_class.class_size

    @property
    def chunks(self) -> [int]:
        return self.__per_class.chunks

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, count={self.count:d}"
        return (f"{Color.colorify('PerClass', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"PerClass(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Number chunks: {0:d}".format(self.count))
        msg.append("Maximal number chunks: {0:d}".format(self.max_count))
        msg.append("Class size: {0:d}".format(self.class_size))

        for _i in range(self.count):
            msg.append("\tChunk #{0:d}: {1:#x}".format(_i, self.chunks[_i]))

        return "\n".join(msg)

        
    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"



@register
class ScudoHeapCommand(GenericCommand):
    """Base command to get information about the Scudo heap structure."""

    _cmdline_ = "scudo"
    _syntax_  = f"{_cmdline_} (chunk|regions|region|batchgroup)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        self.usage()
        return

@register
class ScudoSetupCommand(GenericCommand):
    """Base command to get information about the Scudo heap structure."""

    _cmdline_ = "scudo setup"
    _syntax_  = f"{_cmdline_} [-h]"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    def do_invoke(self, _: List[str]) -> None:
        gdb.execute("set environment SCUDO_OPTIONS thread_local_quarantine_size_kb=5:quarantine_size_kb=10:quarantine_max_chunk_size=2048")
        gdb.execute("set environment LD_PRELOAD ./libscudo-linux.so")
        return
    

@register
class ScudoHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk.
    See https://un1fuzz.github.io/articles/scudo_internals.html#a3_2_3."""

    _cmdline_ = "scudo chunk"
    _syntax_  = f"{_cmdline_} [-h] [--allow-unaligned] address"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"address": ""}, {"--allow-unaligned": True})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.address:
            err("Missing chunk address")
            self.usage()
            return

        addr = parse_address(args.address)
        current_chunk = ScudoChunk(addr, allow_unaligned=args.allow_unaligned)

        gef_print(current_chunk.psprint())

        return

    


@register
class ScudoHeapRegionsCommand(GenericCommand):
    """Display information on all the available regions.
    See https://un1fuzz.github.io/articles/scudo_internals.html#a3_2_3."""

    _cmdline_ = "scudo regions"
    _syntax_  = f"{_cmdline_} [-h]"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        region_info_array_base = search_for_scudo_region_info()

        config = Config()

        region_info = [ScudoRegionInfo("")]
        gef_print(str(region_info[0]))

        for i in range(1, config.num_classes):
            addr = parse_address(f"{region_info[0].address}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*i}")
            region_info += [ScudoRegionInfo(f"{addr:#x}")]
            gef_print(str(region_info[-1]))
    

        return

@register
class ScudoHeapRegionCommand(GenericCommand):
    """Display information on a specific region either by index or by address.
    See https://un1fuzz.github.io/articles/scudo_internals.html#a3_2_3."""

    _cmdline_ = "scudo region"
    _syntax_  = f"{_cmdline_} [-h] [--address 0xADDRESS|--size num_bytes|--index class_id]"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({}, {"--address": "", "--size": -1, "--index": 0})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if (args.address != "") + (args.size != -1) + (args.index != 0) > 1:
            err("Specify exactly one way to identify the region")
            self.usage()
            return

        config = Config()

        
        region_info_addr = ""
        if args.address != "":
            region_info_addr = parse_address(args.address)
        elif args.size >= 0:
            index = 0
            size = (config.min_alignment * math.ceil(args.size / config.min_alignment)) + (config.min_alignment * math.ceil(ctypes.sizeof(ScudoChunk.malloc_chunk_t()) / config.min_alignment))
            while index < config.num_classes:
                gef_print(f"{index}    {config.class_size_list[index]}")
                if size <= config.class_size_list[index]:
                    break
                index += 1
            region_info_addr = parse_address(f"{search_for_scudo_region_info()}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*index}")
        else:
            region_info_addr = parse_address(f"{search_for_scudo_region_info()}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*args.index}")
            
        region_info = ScudoRegionInfo(f"{region_info_addr:#x}")
        gef_print(region_info.psprint())
    

        return

@register
class ScudoBatchGroupCommand(GenericCommand):
    """Display information on a batch group.
    See TODO."""

    _cmdline_ = "scudo batchgroup"
    _syntax_  = f"{_cmdline_} [-h] [--number] address"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"address": ""}, {"--number": 1})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.address:
            err("Missing batch group address")
            self.usage()
            return

        addr = parse_address(args.address)
        current_group = ScudoBatchGroup(addr)

        if args.number > 1:
            for _i in range(args.number):
                if current_group.sizeof == 0:
                    break

                gef_print(str(current_group))
                next_group_addr = current_group.next_addr
                if not Address(value=next_group_addr).valid:
                    break

                next_group = current_group.get_next_batch_group()
                if next_group is None:
                    break

                current_group = next_group
        else:
            gef_print(current_group.psprint())
        return

@register
class ScudoTransferBatchCommand(GenericCommand):
    """Display information on a transfer batch.
    See TODO."""

    _cmdline_ = "scudo transferbatch"
    _syntax_  = f"{_cmdline_} [-h] [--number] address"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"address": ""}, {"--number": 1})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.address:
            err("Missing transfer batch address")
            self.usage()
            return

        addr = parse_address(args.address)
        current_tb = ScudoTransferBatch(addr)

        if args.number > 1:
            for _i in range(args.number):
                if current_tb.sizeof == 0:
                    break

                gef_print(str(current_tb))
                next_tb_addr = current_tb.next_addr
                if not Address(value=next_tb_addr).valid:
                    break

                next_tb = current_tb.get_next_transfer_batch()
                if next_tb is None:
                    break

                current_tb = next_tb
        else:
            gef_print(current_tb.psprint())
        return

@register
class ScudoPerClassCommand(GenericCommand):
    """Display information on a per class structure.
    See TODO."""

    _cmdline_ = "scudo perclass"
    _syntax_  = f"{_cmdline_} [-h] index"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"index": 0}, {})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        
        per_class_addr = parse_address(f"{search_for_scudo_per_class_array()}+{ctypes.sizeof(ScudoPerClass.per_class_t())*args.index}")

        per_class = ScudoPerClass(f"{per_class_addr:#x}")

        gef_print(per_class.psprint())

        return
