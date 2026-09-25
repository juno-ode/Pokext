# pokexhl.py — high-level pokext API (Frida-flavored)
# install to /usr/local/share/pokex/pokexhl.py so `import pokexhl` works
import struct
import threading
import time
import builtins

_target = builtins.target


# ==================== NativePointer ====================

class NativePointer:
    __slots__ = ("addr",)
    def __init__(self, addr):
        if isinstance(addr, NativePointer): self.addr = addr.addr
        elif isinstance(addr, str):          self.addr = int(addr, 16)
        else:                                self.addr = int(addr)

    def __repr__(self):  return f"ptr(0x{self.addr:x})"
    def __int__(self):   return self.addr
    def __eq__(self, o): return int(self) == int(o)
    def __hash__(self):  return hash(self.addr)
    def __bool__(self):  return self.addr != 0

    def __add__(self, n): return NativePointer(self.addr + int(n))
    def __sub__(self, n): return NativePointer(self.addr - int(n))
    def add(self, n):     return self + n
    def sub(self, n):     return self - n

    # ----- reads -----
    def read_i8 (self): return _target.read(self.addr, "i8")
    def read_u8 (self): return _target.read(self.addr, "u8")
    def read_i16(self): return _target.read(self.addr, "i16")
    def read_u16(self): return _target.read(self.addr, "u16")
    def read_i32(self): return _target.read(self.addr, "i32")
    def read_u32(self): return _target.read(self.addr, "u32")
    def read_i64(self): return _target.read(self.addr, "i64")
    def read_u64(self): return _target.read(self.addr, "u64")
    def read_f32(self): return _target.read(self.addr, "f32")
    def read_f64(self): return _target.read(self.addr, "f64")
    def read_ptr(self): return NativePointer(_target.read_ptr(self.addr))
    def read_bytes(self, n): return _target.read_bytes(self.addr, n)
    def read_cstr(self, maxlen=256): return _target.read_cstr(self.addr, maxlen)

    # ----- writes -----
    def write_i8 (self, v): _target.write(self.addr, v, "i8")
    def write_u8 (self, v): _target.write(self.addr, v, "u8")
    def write_i16(self, v): _target.write(self.addr, v, "i16")
    def write_u16(self, v): _target.write(self.addr, v, "u16")
    def write_i32(self, v): _target.write(self.addr, v, "i32")
    def write_u32(self, v): _target.write(self.addr, v, "u32")
    def write_i64(self, v): _target.write(self.addr, v, "i64")
    def write_u64(self, v): _target.write(self.addr, v, "u64")
    def write_f32(self, v): _target.write(self.addr, v, "f32")
    def write_f64(self, v): _target.write(self.addr, v, "f64")
    def write_bytes(self, b): _target.write_bytes(self.addr, b)
    def write_cstr (self, s): _target.write_cstr(self.addr, s)

    def follow(self, *offsets):
        """p.follow(0x10, 0x8, 0x40) — deref pointer, add offset, repeat."""
        cur = self.addr
        for off in offsets:
            cur = _target.follow(cur, [int(off)])
        return NativePointer(cur)


# ==================== Module ====================

class Module:
    def __init__(self, m):
        self._m = m
        self._sym_cache = {}

    @property
    def name(self): return self._m.name
    @property
    def path(self): return self._m.path
    @property
    def base(self): return NativePointer(self._m.base)
    @property
    def size(self): return self._m.size

    def symbol(self, name):
        if name in self._sym_cache:
            return self._sym_cache[name]
        try:
            a = NativePointer(self._m.symbol(name))
        except KeyError:
            return None
        self._sym_cache[name] = a
        return a

    def __repr__(self):
        return f"Module({self.name!r}, base=0x{self._m.base:x})"


# ==================== NativeFunction ====================

class NativeFunction:
    def __init__(self, addr):
        self.addr = NativePointer(addr).addr

    def call(self, *args, ret="i32"):
        has_struct = any(isinstance(a, tuple) for a in args)
        if has_struct:
            return _target.call_struct(hex(self.addr), args, ret=ret)
        return _target.call(hex(self.addr), args, ret=ret)

    __call__ = call


# ==================== Scanner ====================

class Scanner:
    def __init__(self, pattern, module=None):
        self.pattern = pattern
        self.module  = module
        self._hits   = None
        self._idx    = 0

    def _load(self):
        if self._hits is None:
            raw = _target.scan_all(self.pattern, module=self.module) if self.module \
                  else _target.scan_all(self.pattern)
            self._hits = [NativePointer(h) for h in raw]
            self._idx  = 0

    def first(self):
        self._load()
        if not self._hits: return None
        self._idx = 1
        return self._hits[0]

    def next(self):
        self._load()
        if self._idx >= len(self._hits): return None
        h = self._hits[self._idx]
        self._idx += 1
        return h

    def all(self):
        self._load()
        return list(self._hits)

    def __len__(self):
        self._load()
        return len(self._hits)

    def __iter__(self):
        self._load()
        return iter(self._hits)


# ==================== Watcher ====================

class Watcher:
    """Poll an address in the target, fire callbacks when it changes.
    Not in-process like Frida's Interceptor, but close enough for value watching."""

    def __init__(self, addr, type_="i32", interval=0.05):
        self.addr     = NativePointer(addr)
        self.type     = type_
        self.interval = interval
        self._cbs     = []
        self._thread  = None
        self._run     = False
        self._last    = None

    def on_change(self, fn):
        """fn(old_value, new_value)"""
        self._cbs.append(fn)
        return self

    def _loop(self):
        try:
            self._last = _target.read(self.addr.addr, self.type)
        except Exception:
            return
        while self._run:
            time.sleep(self.interval)
            try:
                cur = _target.read(self.addr.addr, self.type)
            except Exception:
                continue
            if cur != self._last:
                old, self._last = self._last, cur
                for cb in self._cbs:
                    try: cb(old, cur)
                    except Exception as e: print(f"[watch cb] {e}")

    def start(self):
        if self._thread and self._thread.is_alive(): return self
        self._run = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._run = False

    def wait(self):
        try:
            while self._run: time.sleep(0.1)
        except KeyboardInterrupt:
            self.stop()


# ==================== Process ====================

class Process:
    def __init__(self, tgt=None):
        self._t = tgt if tgt is not None else _target

    @property
    def pid(self):  return self._t.pid
    @property
    def base(self): return NativePointer(self._t.base)
    @property
    def exe(self):  return self._t.exe

    def module(self, name):  return Module(self._t.module(name))
    def modules(self):       return [Module(m) for m in self._t.modules()]

    def ptr(self, addr):     return NativePointer(addr)
    def sym(self, name):     return NativePointer(self._t.find(name))

    def fn(self, name_or_addr):
        if isinstance(name_or_addr, NativePointer):
            return NativeFunction(name_or_addr.addr)
        if isinstance(name_or_addr, int):
            return NativeFunction(name_or_addr)
        if isinstance(name_or_addr, str) and name_or_addr.startswith("0x"):
            return NativeFunction(int(name_or_addr, 16))
        return NativeFunction(self._t.find(name_or_addr))

    def scan(self, pattern, module=None):
        return Scanner(pattern, module)

    def read(self, addr, type_="i32"):
        return self._t.read(NativePointer(addr).addr, type_)

    def write(self, addr, val, type_="i32"):
        self._t.write(NativePointer(addr).addr, val, type_)

    def alloc(self, size):
        """mmap RWX memory in the target; returns a NativePointer."""
        mmap_addr = None
        for m in self._t.modules():
            if "libc" in m.name:
                try: mmap_addr = m.symbol("mmap"); break
                except KeyError: continue
        if not mmap_addr:
            raise RuntimeError("libc.so has no mmap export")
        PROT_RWX = 0x07
        MAP_PRIVATE_ANON = 0x02 | 0x20
        r = self._t.call(hex(mmap_addr),
                         (0, size, PROT_RWX, MAP_PRIVATE_ANON, -1, 0),
                         ret="i64")
        if r < 0:
            raise RuntimeError(f"mmap failed: {r}")
        return NativePointer(r)

    def watch(self, addr, type_="i32", interval=0.05):
        return Watcher(addr, type_, interval)

    def hook(self, sym, repl, prologue=None):
        """Inline hook. Returns a NativeFunction wrapping the trampoline
        (which runs the original function's prologue)."""
        if prologue is None:
            tramp = self._t.hook_inline(sym, repl)
        else:
            tramp = self._t.hook_inline(sym, repl, prologue=prologue)
        return NativeFunction(tramp)

    def unhook(self, sym):
        self._t.unhook(sym)

    def patch(self, addr, data):
        self._t.patch(NativePointer(addr).addr, data)
