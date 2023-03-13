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






@register
class ScudoHeapCommand(GenericCommand):
    """Base command to get information about the Scudo heap structure."""

    _cmdline_ = "scudo"
    _syntax_  = f"{_cmdline_} (chunk)"#|chunks|bins|arenas|set-arena)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        self.usage()
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
