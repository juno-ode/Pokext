# pokext

External runtime memory patcher for Linux x86-64. Resolves symbols, scans
memory, hooks functions, and runs Python scripts against a live target
process — all from outside the target.

```
    ____       __          
   / __ \____  / /_____     
  / /_/ / __ \/ //_/ _ \    
 / ____/ /_/ / ,< /  __/    
/_/    \____/_/|_|\___/     v0.4.4
```

## What it is

pokext is an *external* patcher. It never injects code into the target.
It uses kernel syscalls (`process_vm_readv/writev`, `ptrace`) to:

- Resolve symbols by name in any loaded module (main exe + every `.so`)
- Read/write int8/16/32/64, float, double, pointers, strings, raw bytes
- Scan memory by byte pattern with `??` wildcards
- Walk multi-level pointer chains
- Hook functions with a trampoline (call the original from your replacement)
- Call functions inside the target — including library functions with struct args
- Drive everything from an embedded Python script

## What it isn't

pokext has no knowledge of any specific game or engine. It's a general
memory tool, the same category as gdb and Frida. Engine-specific helpers
(cvar access for id Tech engines, entity walking for Unity, etc.) live in
separate **bridge** libraries that import `pokexhl` and layer on top.

## Requirements

- Linux x86-64
- Python 3.8+ with dev headers (`python3-dev` / `python3-devel`)
- `sudo` or `CAP_SYS_PTRACE` (ptrace is restricted by default)
- `gcc`

Debian / Ubuntu:
```bash
sudo apt install build-essential python3-dev
```

Fedora / RHEL:
```bash
sudo dnf install gcc python3-devel
```

Arch:
```bash
sudo pacman -S base-devel python
```

## Install

```bash
git clone https://github.com/<you>/pokext.git
cd pokext
./install.sh
```

That builds the binary, installs it to `/usr/local/bin/pokext`, and copies
`pokexhl.py` to `/usr/local/share/pokex/`.

### Manual

```bash
gcc -O2 -o pokext src/pokext.c $(python3-config --includes --embed --ldflags)
sudo cp pokext /usr/local/bin/pokext
sudo mkdir -p /usr/local/share/pokex
sudo cp lib/pokexhl.py /usr/local/share/pokex/
```

Or with make:

```bash
make
sudo make install
```

## Uninstall

```bash
./uninstall.sh
```

or

```bash
sudo make uninstall
```

## Usage

```bash
sudo pokext <pid> <script.py> [--no-banner]
```

`<pid>` is the target process. `<script.py>` is a Python script that
receives a `target` object in its globals. Everything else is your script.

### Hello world

`examples/hello.py`:

```python
import pokexhl as px

p = px.Process()
print(f"attached to {p.exe} (pid {p.pid})")
print(f"base: {p.base}")

for m in p.modules()[:5]:
    print(f"  {m.name} @ {m.base}")
```

Run:
```bash
sudo pokext $(pidof -s mytarget) examples/hello.py
```

## API — `pokexhl`

The high-level Python library mirrors Frida's shape. This is what you write
scripts against.

### Process / modules

```python
import pokexhl as px
p = px.Process()

p.pid                # int
p.base               # NativePointer
p.exe                # str
p.modules()          # list[Module]
p.module("libc.so.6")   # Module (raises KeyError)
p.sym("score")       # NativePointer
p.fn("GetTime")      # NativeFunction
```

### NativePointer

```python
ptr = p.sym("score")
ptr = p.base.add(0x1000)
ptr = p.ptr(0x7f1234)

# read
ptr.read_i8()    ptr.read_u8()
ptr.read_i16()   ptr.read_u16()
ptr.read_i32()   ptr.read_u32()
ptr.read_i64()   ptr.read_u64()
ptr.read_f32()   ptr.read_f64()
ptr.read_ptr()                 # -> NativePointer
ptr.read_bytes(n)              # -> bytes
ptr.read_cstr(maxlen=256)      # -> str

# write
ptr.write_i32(1337)
ptr.write_f32(2.5)
ptr.write_cstr("hello")
ptr.write_bytes(b"\x90\x90")

# pointer math
ptr.add(0x10)
ptr.follow(0x10, 0x8, 0x40)    # deref, add, deref, add, ...
```

### Scan

```python
scan = p.scan("48 8B 05 ?? ?? ?? ??")   # ?? byte wildcard, 4? nibble
scan.first()      # -> NativePointer or None
scan.all()        # -> list[NativePointer]
scan.next()
len(scan)

p.scan("DE AD", module="libc.so.6")     # restrict to one module
```

### Call into the target

```python
p.fn("GetFPS")()
p.fn("SetTargetFPS")(240)
p.fn("GetFrameTime").call(ret="f32")
p.fn("GetTime").call(ret="f64")

# Struct-by-value
p.fn("DrawSphere").call(
    ("v3", 10.0, 5.0, 10.0),
    ("f",  3.0),
    ("i",  0xFF0000FF),
)
```

Arg tags: `("i",v)` `("f",v)` `("v2",x,y)` `("v3",x,y,z)` `("v4",x,y,z,w)`.

### Hooks

```python
orig = p.hook("add_score", "add_score_boost")   # inline, w/ trampoline
orig.call((10,))                                 # run the original
p.unhook("add_score")

p.patch(addr, b"\x90" * 8)                       # raw byte patch
p.hooks()                                        # list active
```

### Watchers (polling callbacks)

```python
w = p.watch(addr, "i32", interval=0.05)
w.on_change(lambda old, new: print(f"{old} -> {new}"))
w.start()
w.stop()
```

### Allocate memory in the target

```python
buf = p.alloc(4096)
buf.write_cstr("hello")
```

## Writing your own bridge

pokext has no game-specific knowledge. A bridge is a small Python library
that imports `pokexhl` and encodes the target's known layout — struct
offsets, cvar names, pointer chains — so cheat scripts stay short.

```python
# mygame.py — bridge for MyGame
import pokexhl as px

class MyGame:
    def __init__(self):
        self.p = px.Process()
        self.player = self.p.sym("player_entity")

    @property
    def health(self):
        return self.player.add(0x40).read_i32()

    @health.setter
    def health(self, v):
        self.player.add(0x40).write_i32(v)
```

```python
# cheat.py — uses the bridge
from mygame import MyGame
g = MyGame()
while True:
    g.health = 9999
```

Bridges live in their own repos and are installed separately. They are
just Python files on `sys.path`.

## Limitations

pokext is external, which means:

- **No managed-runtime access.** Unity IL2CPP, Mono, Java, Unreal Blueprint
  state is not directly reachable through pokext primitives.
- **No in-process callbacks.** Hooks run in the target but can't call back
  into your Python during execution. Use `watch()` for polling.
- **No kernel anti-cheat bypass.** `ptrace` is blocked at the kernel level
  by EAC, BattlEye, Vanguard and similar.
- **Single-threaded attach.** All threads share address space, so patching
  works, but calls into a multi-threaded target race.
- **x86-64 only.** ARM64 support is a port of the register layer, not a
  recompile.

## Legal

pokext is a research and development tool. Use it on processes you own or
have permission to inspect. Using it against software you don't control,
or in online games with anti-cheat, will get you banned and may violate the
game's terms of service. The author assumes no responsibility for misuse.

## License

MIT — see `LICENSE`.
