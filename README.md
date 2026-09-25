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

<p align="center">
  <a href="docs/cheatsheet.html"><b>📖 Cheat Sheet</b></a>
  &nbsp;·&nbsp;
  <a href="#install">Install</a>
  &nbsp;·&nbsp;
  <a href="#usage">Usage</a>
  &nbsp;·&nbsp;
  <a href="examples/">Examples</a>
  &nbsp;·&nbsp;
  <a href="#limitations">Limitations</a>
</p>

> **Full API reference:** [`docs/cheatsheet.html`](docs/cheatsheet.html) — every
> method, every type, every example. Single HTML file, no dependencies.

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
the Python libs from `Pylib/` to `/usr/local/share/pokex/`.

### Manual

```bash
gcc -O2 -o pokext src/pokext.c $(python3-config --includes --embed --ldflags)
sudo cp pokext /usr/local/bin/pokext
sudo mkdir -p /usr/local/share/pokex
sudo cp Pylib/*.py /usr/local/share/pokex/
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

`examples/01_hello.py`:

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
sudo pokext $(pidof -s mytarget) examples/01_hello.py
```

## Cheat sheet

Everything you need to write scripts lives in
[`docs/cheatsheet.html`](docs/cheatsheet.html):

- **Both APIs** — the raw `target` object and the high-level `pokexhl` wrapper,
  side by side
- **Full type table** — every read/write variant
- **Scan syntax** — wildcards, module restriction
- **Call tags** — struct-by-value argument packing
- **Hooks** — redirects, trampolines, byte patches
- **Watchers** — polling callbacks
- **Common patterns** — scan-and-pin, struct walking, hook-and-log
- **Debugging table** — every error and its fix
- **Copy buttons** on every code block
- **Search** — <kbd>Ctrl-F</kbd> to jump to any method

Open it locally, or enable GitHub Pages (repo → Settings → Pages → `/docs`)
and it's served at `https://<you>.github.io/pokext/cheatsheet.html`.

## Examples

Nine working scripts in [`examples/`](examples/), from hello-world through
hooking and calling functions:

| # | File | Concept |
|---|---|---|
| 01 | [`01_hello.py`](examples/01_hello.py) | Attach, list modules, read memory |
| 02 | [`02_read_write.py`](examples/02_read_write.py) | Read/write globals by symbol |
| 03 | [`03_scan_pin.py`](examples/03_scan_pin.py) | Find a value by scanning, pin it |
| 04 | [`04_pattern_scan.py`](examples/04_pattern_scan.py) | AOB scan for code patterns |
| 05 | [`05_pointer_chain.py`](examples/05_pointer_chain.py) | Multi-level pointer following |
| 06 | [`06_hook.py`](examples/06_hook.py) | Redirect a function with a trampoline |
| 07 | [`07_call_function.py`](examples/07_call_function.py) | Call functions inside the target |
| 08 | [`08_watch.py`](examples/08_watch.py) | Poll a value and fire a callback |
| 09 | [`09_multi_process.py`](examples/09_multi_process.py) | Attach to a second process |

Each one teaches a single concept and can be run against any Linux target.

## Writing a bridge

A bridge is a small Python library that encodes your target's known layout,
so cheat scripts stay short. Bridges live in their own repos.

```python
# mygame.py
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
# cheat.py
from mygame import MyGame
import time

g = MyGame()
while True:
    g.health = 9999
    time.sleep(0.1)
```

Full bridge-writing guide in the [cheat sheet](docs/cheatsheet.html).

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

## Roadmap

- **v0.4.5** — multi-threaded ptrace attach
- **v0.5.0** — in-process callbacks via ring buffer + injected stub
- **Later** — ARM64 register layer, formal bridge template

## Legal

pokext is a research and development tool. Use it on processes you own or
have permission to inspect. Using it against software you don't control,
or in online games with anti-cheat, will get you banned and may violate the
game's terms of service. The author assumes no responsibility for misuse.

## License

MIT — see [`LICENSE`](LICENSE).
