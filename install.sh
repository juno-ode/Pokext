#!/usr/bin/env bash
#
# pokext installer
# builds the binary, installs to $PREFIX/bin, copies Python libs to $PREFIX/share/pokex
#
set -euo pipefail

# ---- configurable paths ----

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
LIBDIR="$PREFIX/share/pokex"

# ---- colors ----

if [ -t 1 ]; then
    C_RED=$'\033[31m'
    C_GRN=$'\033[32m'
    C_YLW=$'\033[33m'
    C_CYN=$'\033[36m'
    C_DIM=$'\033[2m'
    C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_DIM=""; C_RST=""
fi

msg()  { printf "%s[*]%s %s\n" "$C_CYN" "$C_RST" "$*"; }
ok()   { printf "%s[+]%s %s\n" "$C_GRN" "$C_RST" "$*"; }
warn() { printf "%s[!]%s %s\n" "$C_YLW" "$C_RST" "$*" >&2; }
die()  { printf "%s[x]%s %s\n" "$C_RED" "$C_RST" "$*" >&2; exit 1; }

# ---- locate repo root ----

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[ -f src/pokext.c ]  || die "src/pokext.c not found — run from the repo root"
[ -f Pylib/pokexhl.py ] || die "Pylib/pokexhl.py not found — run from the repo root"

# ---- check tools ----

command -v gcc           >/dev/null || die "gcc not found. install build tools first."
command -v python3       >/dev/null || die "python3 not found."
command -v python3-config >/dev/null || die "python3-config not found. install python3-dev / python3-devel."

# ---- check py embed flags ----

if ! python3-config --embed >/dev/null 2>&1; then
    warn "python3-config lacks --embed (Python < 3.8). Falling back to --ldflags."
    PY_LDFLAGS="$(python3-config --ldflags)"
else
    PY_LDFLAGS="$(python3-config --embed --ldflags)"
fi
PY_INCLUDES="$(python3-config --includes)"

# ---- build ----

msg "building pokext..."
gcc -O2 -Wall -o pokext src/pokext.c $PY_INCLUDES $PY_LDFLAGS \
    || die "build failed"

ok "built ./pokext"

# ---- install binary ----

msg "installing binary to $BINDIR/pokext"
sudo install -d "$BINDIR"
sudo install -m 755 pokext "$BINDIR/pokext"
ok "installed $BINDIR/pokext"

# ---- install python libs ----

msg "installing Python libs to $LIBDIR"
sudo install -d "$LIBDIR"

# Copy every .py in Pylib/ — this picks up pokexhl.py and any future modules
found_any=0
for f in Pylib/*.py; do
    [ -e "$f" ] || continue
    sudo install -m 644 "$f" "$LIBDIR/"
    ok "installed $LIBDIR/$(basename "$f")"
    found_any=1
done

[ "$found_any" = "1" ] || die "no .py files found in Pylib/"

# ---- done ----

echo
ok "pokext installed"
echo
echo "${C_DIM}usage:${C_RST}"
echo "  sudo pokext \$(pidof -s <target>) <script.py>"
echo
echo "${C_DIM}libs installed to:${C_RST} $LIBDIR"
echo "${C_DIM}binary:${C_RST}           $BINDIR/pokext"
echo
