import ctypes
import gdb
import enum

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

SCUDO_REGION_INFO_ARRAY_DEFAULT_NAME = "RegionInfoArray"
SCUDO_CACHE_LINE_SIZE = 64
    
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
            ("release_last_byttes", pointer),
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

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, region_begin={self.region_beg:#x}, " \
                f"mapped={self.mapped_user:#x}, allocated={self.allocated_user:#x}"
        return (f"{Color.colorify('Region', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"ScudoRegionInfo(address={self.__address:#x}, size={self._sizeof})"


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
        return self.__region.pushed_block_at_last_release

    @property
    def ranges_released(self) -> int:
        return self.__region.ranges_released

    @property
    def last_released_bytes(self) -> int:
        return self.__region.last_released_bytes

    @property
    def last_release_at_ns(self) -> int:
        return self.__region.last_release_at_ns






@register
class ScudoHeapCommand(GenericCommand):
    """Base command to get information about the Scudo heap structure."""

    _cmdline_ = "scudo"
    _syntax_  = f"{_cmdline_} (chunk|regions)"#|chunks|bins|arenas|set-arena)"

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
#        args : argparse.Namespace = kwargs["arguments"]

        region_info_array_base = search_for_scudo_region_info()

        max_num_cached_hint = -1
        num_classes = -1
        max_size = -1
        largest_class_id = -1
        batch_class_id = -1
        class_size_list = []
        
        try:
            gdb.parse_and_eval(f"scudo::DefaultConfig")                
        except gdb.error as e:
            if "Cannot look up value of a typedef" in str(e):
                min_size_log = 5
                mid_size_log = 8
                max_size_log = 17
                num_bits = 3
                max_num_cached_hint = 14
                max_bytes_cached_log = 10
                size_delta = 0
                mid_class = int((1 << mid_size_log) / (1 << min_size_log))
            
                S = num_bits - 1
                M = (1 << S) - 1
                max_size = (1 << max_size_log) + size_delta
                num_classes = mid_class + ((max_size_log - mid_size_log) << S) + 1
                largest_class_id = num_classes - 1
                batch_class_id = 0

                for i in range(num_classes):
                    if i == 0:
                        class_size_list += [-1]
                        continue
                    if i <= mid_class:
                        class_size_list += [(i << min_size_log) + size_delta]
                        continue

                    cid = i - mid_class
                    T = (1 << mid_size_log) << (cid >> S)

                    class_size_list += [T + (T >> S) * (cid & M) + size_delta]

            else:
                try:
                    gdb.parse_and_eval(f"scudo::AndroidConfig")
                except gdb.error as e:
                    if "Cannot look up value of a typedef" in str(e):
                        min_size_log = 4
                        mid_size_log = 6
                        max_size_log = 16
                        num_bits = 7
                        max_num_cached_hint = 13
                        max_bytes_cached_log = 13
                        size_delta = 16
                        
                        class_size_list = [-1, 0x00020, 0x00030, 0x00040, 0x00050,
                                           0x00060, 0x00070, 0x00090, 0x000b0, 0x000c0,
                                           0x000e0, 0x00120, 0x00160, 0x001c0, 0x00250,
                                           0x00320, 0x00450, 0x00670, 0x00830, 0x00a10,
                                           0x00c30, 0x01010, 0x01210, 0x01bd0, 0x02210,
                                           0x02d90, 0x03790, 0x04010, 0x04810, 0x05a10,
                                           0x07310, 0x08210, 0x10010,]
                        
                        num_classes = len(class_size_list) - 1
                        largest_class_id = num_classes - 1
                        batch_class_id = 0
                        max_size = class_size_list[-1]


        region_info = [ScudoRegionInfo("")]
        
        gef_print(str(region_info[0]))

        for i in range(1, num_classes):
            addr = parse_address(f"{region_info[0].address}+{region_info[0].sizeof*i}")
            region_info += [ScudoRegionInfo(f"{addr:#x}")]
            gef_print(str(region_info[-1]))
    

        return
