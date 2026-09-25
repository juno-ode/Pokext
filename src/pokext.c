// pokex.c — v0.4.4 runtime memory patcher with CPython
// build: gcc -O2 -o pokex pokex.c $(python3-config --includes --embed --ldflags)
// run  : sudo -E ./pokex <pid> <script.py> [--no-banner]
#define _GNU_SOURCE
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

/* ==================== raw memory primitives ==================== */

static int read_mem(pid_t pid, unsigned long a, void *b, size_t n) {
    struct iovec l = { b, n }, r = { (void *)a, n };
    return process_vm_readv(pid, &l, 1, &r, 1, 0) == (ssize_t)n;
}
static int write_mem(pid_t pid, unsigned long a, const void *b, size_t n) {
    struct iovec l = { (void *)b, n }, r = { (void *)a, n };
    return process_vm_writev(pid, &l, 1, &r, 1, 0) == (ssize_t)n;
}

/* ==================== ELF symbol lookup ==================== */

static unsigned long find_symbol64(int fd, const char *want, int *is_pie) {
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) return 0;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (is_pie) *is_pie = (eh.e_type == ET_DYN);
    unsigned long result = 0;
    for (int i = 0; i < eh.e_shnum && !result; i++) {
        Elf64_Shdr sh;
        if (pread(fd, &sh, sizeof(sh),
                  eh.e_shoff + (off_t)i * eh.e_shentsize) != (ssize_t)sizeof(sh)) continue;
        if ((sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) || !sh.sh_entsize) continue;
        Elf64_Shdr strsh;
        if (pread(fd, &strsh, sizeof(strsh),
                  eh.e_shoff + (off_t)sh.sh_link * eh.e_shentsize) != (ssize_t)sizeof(strsh))
            continue;
        char *strtab = malloc(strsh.sh_size);
        if (!strtab) continue;
        if (pread(fd, strtab, strsh.sh_size, strsh.sh_offset) != (ssize_t)strsh.sh_size) {
            free(strtab); continue;
        }
        size_t n = sh.sh_size / sh.sh_entsize;
        for (size_t j = 0; j < n; j++) {
            Elf64_Sym sym;
            if (pread(fd, &sym, sizeof(sym),
                      sh.sh_offset + (off_t)j * sh.sh_entsize) != (ssize_t)sizeof(sym))
                continue;
            if (sym.st_name && strcmp(strtab + sym.st_name, want) == 0) {
                result = sym.st_value; break;
            }
        }
        free(strtab);
    }
    return result;
}

/* ==================== /proc/pid/maps ==================== */

#define MAX_MODULES 512

typedef struct {
    char path[512];
    char name[256];
    unsigned long base;
    unsigned long end;
} ModuleInfo;

typedef struct {
    unsigned long start, end, offset;
    char perms[8];
    char path[512];
} RegionInfo;

static int enumerate_modules(pid_t pid, ModuleInfo *out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && n < max) {
        unsigned long s, e, off, inode;
        char perms[8], dev[16], name[512] = {0};
        int parsed = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511s",
                            &s, &e, perms, &off, dev, &inode, name);
        if (parsed < 6) continue;
        if (name[0] == 0 || name[0] == '[') continue;
        int found = -1;
        for (int i = 0; i < n; i++)
            if (strcmp(out[i].path, name) == 0) { found = i; break; }
        if (found >= 0) {
            if (s < out[found].base) out[found].base = s;
            if (e > out[found].end)  out[found].end  = e;
        } else {
            strncpy(out[n].path, name, 511); out[n].path[511] = 0;
            const char *slash = strrchr(name, '/');
            strncpy(out[n].name, slash ? slash + 1 : name, 255);
            out[n].name[255] = 0;
            out[n].base = s; out[n].end = e;
            n++;
        }
    }
    fclose(f);
    return n;
}

static int enumerate_regions(pid_t pid, RegionInfo *out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && n < max) {
        unsigned long s, e, off, inode;
        char perms[8], dev[16], name[512] = {0};
        int parsed = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511s",
                            &s, &e, perms, &off, dev, &inode, name);
        if (parsed < 4) continue;
        out[n].start = s; out[n].end = e; out[n].offset = off;
        strncpy(out[n].perms, perms, 7); out[n].perms[7] = 0;
        strncpy(out[n].path, name, 511); out[n].path[511] = 0;
        n++;
    }
    fclose(f);
    return n;
}

/* ==================== pattern parsing ==================== */

typedef struct {
    uint8_t *bytes;
    uint8_t *mask;
    size_t   len;
} Pattern;

static Pattern *parse_pattern(const char *s, char *errbuf, size_t errsz) {
    char *clean = malloc(strlen(s) + 1);
    size_t n = 0;
    for (const char *p = s; *p; p++)
        if (!isspace((unsigned char)*p)) clean[n++] = *p;
    clean[n] = 0;
    if (n == 0 || (n % 2) != 0) {
        snprintf(errbuf, errsz, "pattern must be even hex digits (got %zu)", n);
        free(clean); return NULL;
    }
    Pattern *p = malloc(sizeof(*p));
    p->len   = n / 2;
    p->bytes = malloc(p->len);
    p->mask  = malloc(p->len);
    for (size_t i = 0; i < p->len; i++) {
        char a = clean[i*2], b = clean[i*2+1];
        uint8_t byte = 0, m = 0;
        #define NIBBLE(c, shift) do { \
            if ((c) == '?') { } \
            else if ((c) >= '0' && (c) <= '9') { byte |= (uint8_t)((c) - '0') << (shift); m |= (uint8_t)(0xF << (shift)); } \
            else if ((c) >= 'a' && (c) <= 'f') { byte |= (uint8_t)((c) - 'a' + 10) << (shift); m |= (uint8_t)(0xF << (shift)); } \
            else if ((c) >= 'A' && (c) <= 'F') { byte |= (uint8_t)((c) - 'A' + 10) << (shift); m |= (uint8_t)(0xF << (shift)); } \
            else { snprintf(errbuf, errsz, "bad hex char '%c'", (c)); \
                   free(clean); free(p->bytes); free(p->mask); free(p); return NULL; } \
        } while (0)
        NIBBLE(a, 4);
        NIBBLE(b, 0);
        #undef NIBBLE
        p->bytes[i] = byte;
        p->mask[i]  = m;
    }
    free(clean);
    return p;
}

static int pattern_match(const Pattern *p, const uint8_t *data) {
    for (size_t i = 0; i < p->len; i++)
        if ((data[i] & p->mask[i]) != (p->bytes[i] & p->mask[i])) return 0;
    return 1;
}

/* ==================== typed values ==================== */

enum valtype {
    VT_I8, VT_U8, VT_I16, VT_U16, VT_I32, VT_U32,
    VT_I64, VT_U64, VT_F32, VT_F64, VT_PTR,
};

static int parse_type(const char *s, enum valtype *out) {
    if      (!strcmp(s,"i8")  ||!strcmp(s,"int8"))   *out = VT_I8;
    else if (!strcmp(s,"u8")  ||!strcmp(s,"uint8"))  *out = VT_U8;
    else if (!strcmp(s,"i16") ||!strcmp(s,"int16"))  *out = VT_I16;
    else if (!strcmp(s,"u16") ||!strcmp(s,"uint16")) *out = VT_U16;
    else if (!strcmp(s,"i32") ||!strcmp(s,"int")    ||!strcmp(s,"int32")) *out = VT_I32;
    else if (!strcmp(s,"u32") ||!strcmp(s,"uint32")) *out = VT_U32;
    else if (!strcmp(s,"i64") ||!strcmp(s,"int64"))  *out = VT_I64;
    else if (!strcmp(s,"u64") ||!strcmp(s,"uint64")) *out = VT_U64;
    else if (!strcmp(s,"f32") ||!strcmp(s,"float"))  *out = VT_F32;
    else if (!strcmp(s,"f64") ||!strcmp(s,"double")) *out = VT_F64;
    else if (!strcmp(s,"ptr") ||!strcmp(s,"p"))      *out = VT_PTR;
    else return 0;
    return 1;
}

static PyObject *read_typed(pid_t pid, unsigned long addr, enum valtype t) {
    #define RD(T, conv) do { \
        T v; if (!read_mem(pid, addr, &v, sizeof(v))) { PyErr_SetFromErrno(PyExc_OSError); return NULL; } \
        return conv(v); } while (0)
    switch (t) {
        case VT_I8:  RD(int8_t,   PyLong_FromLong);
        case VT_U8:  RD(uint8_t,  PyLong_FromLong);
        case VT_I16: RD(int16_t,  PyLong_FromLong);
        case VT_U16: RD(uint16_t, PyLong_FromLong);
        case VT_I32: RD(int32_t,  PyLong_FromLong);
        case VT_U32: RD(uint32_t, PyLong_FromUnsignedLong);
        case VT_I64: RD(int64_t,  PyLong_FromLongLong);
        case VT_U64: RD(uint64_t, PyLong_FromUnsignedLongLong);
        case VT_F32: RD(float,    PyFloat_FromDouble);
        case VT_F64: RD(double,   PyFloat_FromDouble);
        case VT_PTR: RD(uint64_t, PyLong_FromUnsignedLongLong);
    }
    #undef RD
    PyErr_SetString(PyExc_ValueError, "unknown type");
    return NULL;
}

static int write_typed(pid_t pid, unsigned long addr, PyObject *val, enum valtype t) {
    #define WR_INT(T, get) do { \
        long long v = get(val); if (PyErr_Occurred()) return -1; \
        T b = (T)v; if (!write_mem(pid, addr, &b, sizeof(b))) { PyErr_SetFromErrno(PyExc_OSError); return -1; } return 0; } while (0)
    #define WR_UINT(T, get) do { \
        unsigned long long v = get(val); if (PyErr_Occurred()) return -1; \
        T b = (T)v; if (!write_mem(pid, addr, &b, sizeof(b))) { PyErr_SetFromErrno(PyExc_OSError); return -1; } return 0; } while (0)
    #define WR_FLT(T) do { \
        double d = PyFloat_AsDouble(val); if (PyErr_Occurred()) { \
            PyErr_Clear(); long long i = PyLong_AsLongLong(val); if (PyErr_Occurred()) return -1; d = (double)i; } \
        T f = (T)d; if (!write_mem(pid, addr, &f, sizeof(f))) { PyErr_SetFromErrno(PyExc_OSError); return -1; } return 0; } while (0)
    switch (t) {
        case VT_I8:  WR_INT (int8_t,   PyLong_AsLongLong);
        case VT_U8:  WR_UINT(uint8_t,  PyLong_AsUnsignedLongLong);
        case VT_I16: WR_INT (int16_t,  PyLong_AsLongLong);
        case VT_U16: WR_UINT(uint16_t, PyLong_AsUnsignedLongLong);
        case VT_I32: WR_INT (int32_t,  PyLong_AsLongLong);
        case VT_U32: WR_UINT(uint32_t, PyLong_AsUnsignedLongLong);
        case VT_I64: WR_INT (int64_t,  PyLong_AsLongLong);
        case VT_U64: WR_UINT(uint64_t, PyLong_AsUnsignedLongLong);
        case VT_F32: WR_FLT (float);
        case VT_F64: WR_FLT (double);
        case VT_PTR: WR_UINT(uint64_t, PyLong_AsUnsignedLongLong);
    }
    #undef WR_INT
    #undef WR_UINT
    #undef WR_FLT
    PyErr_SetString(PyExc_ValueError, "unknown type");
    return -1;
}

/* ==================== forward decls ==================== */

typedef struct {
    PyObject_HEAD
    pid_t pid;
    char path[512];
    char name[256];
    unsigned long base;
    unsigned long size;
} Module;

typedef struct HookEntry HookEntry;

typedef struct {
    PyObject_HEAD
    pid_t pid;
    char exe_path[512];
    unsigned long base;
    int is_pie;
    ModuleInfo modules[MAX_MODULES];
    int module_count;
    int modules_loaded;
    struct { char key[256]; unsigned long addr; } cache[256];
    int cache_n;
    HookEntry *hooks;
    int hook_n;
} Target;

static PyTypeObject TargetType;
static PyTypeObject ModuleType;

/* ==================== hooks ==================== */

#define HOOK_MAX 64
#define HOOK_SAVE_MAX 256

struct HookEntry {
    char name[128];
    unsigned long addr;
    unsigned long replacement;
    unsigned long trampoline;
    unsigned char saved[HOOK_SAVE_MAX];
    int saved_len;
    int prologue_size;
    int active;
};

/* ==================== symbol resolution ==================== */

static void ensure_modules(Target *self) {
    if (self->modules_loaded) return;
    self->module_count = enumerate_modules(self->pid, self->modules, MAX_MODULES);
    self->modules_loaded = 1;
}

static unsigned long resolve_in_module(pid_t pid, const char *path,
                                       unsigned long base, const char *sym) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    int is_pie = 1;
    unsigned long off = find_symbol64(fd, sym, &is_pie);
    close(fd);
    if (!off) return 0;
    return base + off;
}

static unsigned long target_resolve(Target *self, const char *name) {
    for (int i = 0; i < self->cache_n; i++)
        if (!strcmp(self->cache[i].key, name)) return self->cache[i].addr;

    unsigned long addr = 0;
    int fd = open(self->exe_path, O_RDONLY);
    if (fd >= 0) {
        int is_pie = 0;
        unsigned long off = find_symbol64(fd, name, &is_pie);
        close(fd);
        if (off) addr = self->base + off;
    }
    if (!addr) {
        ensure_modules(self);
        for (int i = 0; i < self->module_count && !addr; i++) {
            if (strcmp(self->modules[i].path, self->exe_path) == 0) continue;
            addr = resolve_in_module(self->pid, self->modules[i].path,
                                     self->modules[i].base, name);
        }
    }
    if (addr && self->cache_n < 256) {
        strncpy(self->cache[self->cache_n].key, name, 255);
        self->cache[self->cache_n].addr = addr;
        self->cache_n++;
    }
    return addr;
}

static unsigned long find_libc_symbol(Target *self, const char *sym) {
    ensure_modules(self);
    for (int i = 0; i < self->module_count; i++) {
        const char *n = self->modules[i].name;
        if (strstr(n, "libc.so") || strstr(n, "libc-")) {
            unsigned long a = resolve_in_module(self->pid,
                                                self->modules[i].path,
                                                self->modules[i].base,
                                                sym);
            if (a) return a;
        }
    }
    return 0;
}

static unsigned long parse_addr_or_symbol(Target *self, const char *s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return strtoul(s, NULL, 16);
    return target_resolve(self, s);
}

/* ==================== ptrace: single-thread ==================== */

static int get_threads(pid_t pid, pid_t *out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) return 0;
    int n = 0;
    out[n++] = pid;
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] == '.') continue;
        pid_t tid = (pid_t)atoi(e->d_name);
        if (tid > 0 && tid != pid) out[n++] = tid;
    }
    closedir(d);
    return n;
}

static int ptrace_attach_all(pid_t *tids, int n, int *attached_mask) {
    if (n == 0) return 0;
    memset(attached_mask, 0, sizeof(int) * n);

    if (ptrace(PTRACE_ATTACH, tids[0], 0, 0) < 0) return 0;

    int status;
    if (waitpid(tids[0], &status, __WALL) < 0) {
        ptrace(PTRACE_DETACH, tids[0], 0, 0);
        return 0;
    }
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, tids[0], 0, 0);
        errno = ESRCH;
        return 0;
    }
    attached_mask[0] = 1;
    return 1;
}

static void ptrace_detach_all(pid_t *tids, int n, const int *attached_mask) {
    for (int i = 0; i < n; i++)
        if (attached_mask[i])
            ptrace(PTRACE_DETACH, tids[i], 0, 0);
}

/* ==================== ptrace byte patching ==================== */

static int ptrace_poke_bytes(pid_t pid, unsigned long addr, const void *buf, size_t n) {
    const unsigned char *src = buf;
    size_t i = 0;
    while (i < n) {
        unsigned long wa = (addr + i) & ~7UL;
        size_t off = (addr + i) & 7;
        size_t to_copy = 8 - off;
        if (to_copy > n - i) to_copy = n - i;

        unsigned char word_bytes[8];
        if (!read_mem(pid, wa, word_bytes, 8)) return -1;

        memcpy(word_bytes + off, src + i, to_copy);

        long word;
        memcpy(&word, word_bytes, 8);

        if (ptrace(PTRACE_POKETEXT, pid, (void *)wa, (void *)word) < 0) return -1;
        i += to_copy;
    }
    return 0;
}

static int ptrace_peek_bytes(pid_t pid, unsigned long addr, void *buf, size_t n) {
    return read_mem(pid, addr, buf, n) ? 0 : -1;
}

/* ==================== register layout for calls ==================== */

typedef struct {
    int n_int;
    unsigned long ints[6];
    int n_sse;
    float sse[8][4];
    int ret_is_double;
} CallRegs;

static long remote_call_typed(pid_t pid, unsigned long func,
                              const CallRegs *r, double *fret_out)
{
    pid_t tids[256];
    int n_tids = get_threads(pid, tids, 256);
    if (n_tids == 0) { tids[0] = pid; n_tids = 1; }
    int mask[256];
    if (ptrace_attach_all(tids, n_tids, mask) == 0) return -1;

    struct user_regs_struct regs, saved;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
        ptrace_detach_all(tids, n_tids, mask);
        return -1;
    }
    saved = regs;

    unsigned char xbuf[4096], xbuf_saved[4096];
    struct iovec xiov = { xbuf, sizeof(xbuf) };
    int have_xs = (ptrace(PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, &xiov) == 0);
    size_t xlen = have_xs ? xiov.iov_len : 0;
    if (have_xs) memcpy(xbuf_saved, xbuf, xlen);

    struct user_fpregs_struct fp, fp_saved;
    int have_fp = 0;
    if (!have_xs) {
        have_fp = (ptrace(PTRACE_GETFPREGS, pid, 0, &fp) == 0);
        if (have_fp) fp_saved = fp;
    }

    unsigned long int3_addr = (regs.rsp - 0x10000UL) & ~0xFUL;
    unsigned long ret_slot  = ((regs.rsp - 0x1000UL) & ~0xFUL) | 8UL;

    unsigned long orig_int3 = 0, orig_ret = 0;
    int have_int3_orig = 0, have_ret_orig = 0;
    errno = 0;
    long p1 = ptrace(PTRACE_PEEKDATA, pid, (void *)int3_addr, 0);
    if (errno == 0) { have_int3_orig = 1; orig_int3 = (unsigned long)p1; }
    errno = 0;
    long p2 = ptrace(PTRACE_PEEKDATA, pid, (void *)ret_slot, 0);
    if (errno == 0) { have_ret_orig = 1; orig_ret = (unsigned long)p2; }

    unsigned long int3_word = 0xCCCCCCCCCCCCCCCCUL;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)int3_addr, (void *)int3_word) < 0 ||
        ptrace(PTRACE_POKEDATA, pid, (void *)ret_slot,  (void *)int3_addr) < 0) {
        if (have_xs) {
            struct iovec ri = { xbuf_saved, xlen };
            ptrace(PTRACE_SETREGSET, pid, (void *)NT_X86_XSTATE, &ri);
        } else if (have_fp) {
            ptrace(PTRACE_SETFPREGS, pid, 0, &fp_saved);
        }
        ptrace(PTRACE_SETREGS, pid, 0, &saved);
        ptrace_detach_all(tids, n_tids, mask);
        return -1;
    }

    regs.rdi = r->n_int > 0 ? r->ints[0] : 0;
    regs.rsi = r->n_int > 1 ? r->ints[1] : 0;
    regs.rdx = r->n_int > 2 ? r->ints[2] : 0;
    regs.rcx = r->n_int > 3 ? r->ints[3] : 0;
    regs.r8  = r->n_int > 4 ? r->ints[4] : 0;
    regs.r9  = r->n_int > 5 ? r->ints[5] : 0;
    regs.rsp = ret_slot;
    regs.rip = func;

    long result = -1;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) goto restore;

    if (r->n_sse > 0) {
        if (have_xs) {
            for (int i = 0; i < r->n_sse && i < 8; i++)
                memcpy(xbuf + 160 + i * 16, r->sse[i], 16);
            struct iovec wi = { xbuf, xlen };
            ptrace(PTRACE_SETREGSET, pid, (void *)NT_X86_XSTATE, &wi);
        } else if (have_fp) {
            for (int i = 0; i < r->n_sse && i < 8; i++)
                memcpy(&fp.xmm_space[i * 4], r->sse[i], 16);
            ptrace(PTRACE_SETFPREGS, pid, 0, &fp);
        }
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) == 0) {
        int status;
        if (waitpid(pid, &status, __WALL) >= 0 && WIFSTOPPED(status)) {
            struct user_regs_struct after;
            if (ptrace(PTRACE_GETREGS, pid, 0, &after) == 0) {
                result = (long)after.rax;

                if (fret_out) {
                    int got = 0;
                    if (have_xs) {
                        unsigned char post[4096];
                        struct iovec pi = { post, sizeof(post) };
                        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, &pi) == 0) {
                            if (r->ret_is_double) {
                                double d; memcpy(&d, post + 160, 8);
                                *fret_out = d;
                            } else {
                                float f; memcpy(&f, post + 160, 4);
                                *fret_out = (double)f;
                            }
                            got = 1;
                        }
                    }
                    if (!got && have_fp) {
                        struct user_fpregs_struct post;
                        if (ptrace(PTRACE_GETFPREGS, pid, 0, &post) == 0) {
                            if (r->ret_is_double) {
                                double d; memcpy(&d, &post.xmm_space[0], 8);
                                *fret_out = d;
                            } else {
                                float f; memcpy(&f, &post.xmm_space[0], 4);
                                *fret_out = (double)f;
                            }
                        }
                    }
                }
            }
        }
    }

restore:
    if (have_int3_orig)
        ptrace(PTRACE_POKEDATA, pid, (void *)int3_addr, (void *)orig_int3);
    if (have_ret_orig)
        ptrace(PTRACE_POKEDATA, pid, (void *)ret_slot,  (void *)orig_ret);

    if (have_xs) {
        struct iovec ri = { xbuf_saved, xlen };
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_X86_XSTATE, &ri);
    } else if (have_fp) {
        ptrace(PTRACE_SETFPREGS, pid, 0, &fp_saved);
    }
    ptrace(PTRACE_SETREGS, pid, 0, &saved);
    ptrace_detach_all(tids, n_tids, mask);
    return result;
}

static long remote_call(pid_t pid, unsigned long func,
                        const long *iargs, int ni,
                        const double *fargs, int nf,
                        double *fret_out)
{
    CallRegs r = {0};
    r.n_int = ni > 6 ? 6 : ni;
    for (int i = 0; i < r.n_int; i++) r.ints[i] = (unsigned long)iargs[i];
    r.n_sse = nf > 8 ? 8 : nf;
    for (int i = 0; i < r.n_sse; i++) r.sse[i][0] = (float)fargs[i];
    return remote_call_typed(pid, func, &r, fret_out);
}

/* ==================== Target: attribute access ==================== */

static PyObject *Target_getattro(PyObject *obj, PyObject *name) {
    PyObject *res = PyObject_GenericGetAttr(obj, name);
    if (res) return res;
    if (!PyErr_ExceptionMatches(PyExc_AttributeError)) return NULL;
    PyErr_Clear();
    Target *self = (Target *)obj;
    const char *n = PyUnicode_AsUTF8(name);
    if (n[0] == '_') { PyErr_Format(PyExc_AttributeError, "%s", n); return NULL; }
    unsigned long addr = target_resolve(self, n);
    if (!addr) { PyErr_Format(PyExc_AttributeError, "symbol '%s' not found", n); return NULL; }
    return read_typed(self->pid, addr, VT_I32);
}

static int Target_setattro(PyObject *obj, PyObject *name, PyObject *value) {
    Target *self = (Target *)obj;
    const char *n = PyUnicode_AsUTF8(name);
    if (!strcmp(n,"pid")||!strcmp(n,"base")||!strcmp(n,"exe")) {
        PyErr_Format(PyExc_AttributeError, "%s is read-only", n); return -1;
    }
    if (n[0] == '_') { PyErr_Format(PyExc_AttributeError, "cannot set '%s'", n); return -1; }
    unsigned long addr = target_resolve(self, n);
    if (!addr) { PyErr_Format(PyExc_AttributeError, "symbol '%s' not found", n); return -1; }
    return write_typed(self->pid, addr, value, VT_I32);
}

/* ==================== basic methods ==================== */

static PyObject *Target_find(Target *self, PyObject *args) {
    const char *name;
    if (!PyArg_ParseTuple(args, "s", &name)) return NULL;
    unsigned long a = target_resolve(self, name);
    if (!a) { PyErr_Format(PyExc_KeyError, "symbol '%s' not found", name); return NULL; }
    return PyLong_FromUnsignedLong(a);
}

static PyObject *Target_read(Target *self, PyObject *args, PyObject *kw) {
    unsigned long addr;
    const char *type = "i32";
    static char *kwlist[] = {"addr", "type", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "k|s", kwlist, &addr, &type)) return NULL;
    enum valtype t;
    if (!parse_type(type, &t)) { PyErr_Format(PyExc_ValueError, "unknown type '%s'", type); return NULL; }
    return read_typed(self->pid, addr, t);
}

static PyObject *Target_write(Target *self, PyObject *args, PyObject *kw) {
    unsigned long addr;
    PyObject *val;
    const char *type = "i32";
    static char *kwlist[] = {"addr", "value", "type", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "kO|s", kwlist, &addr, &val, &type)) return NULL;
    enum valtype t;
    if (!parse_type(type, &t)) { PyErr_Format(PyExc_ValueError, "unknown type '%s'", type); return NULL; }
    if (write_typed(self->pid, addr, val, t) != 0) return NULL;
    Py_RETURN_NONE;
}

static PyObject *Target_read_bytes(Target *self, PyObject *args) {
    unsigned long addr; Py_ssize_t n;
    if (!PyArg_ParseTuple(args, "kn", &addr, &n)) return NULL;
    if (n < 0) { PyErr_SetString(PyExc_ValueError, "negative length"); return NULL; }
    char *buf = malloc(n ? n : 1);
    if (!buf) return PyErr_NoMemory();
    if (!read_mem(self->pid, addr, buf, n)) { free(buf); PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    PyObject *out = PyBytes_FromStringAndSize(buf, n);
    free(buf);
    return out;
}

static PyObject *Target_write_bytes(Target *self, PyObject *args) {
    unsigned long addr; Py_buffer b;
    if (!PyArg_ParseTuple(args, "ky*", &addr, &b)) return NULL;
    int ok = write_mem(self->pid, addr, b.buf, b.len);
    PyBuffer_Release(&b);
    if (!ok) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    Py_RETURN_NONE;
}

static PyObject *Target_read_cstr(Target *self, PyObject *args) {
    unsigned long addr;
    int maxlen = 256;
    if (!PyArg_ParseTuple(args, "k|i", &addr, &maxlen)) return NULL;
    char *buf = malloc(maxlen + 1);
    if (!buf) return PyErr_NoMemory();
    if (!read_mem(self->pid, addr, buf, maxlen)) { free(buf); PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    buf[maxlen] = 0;
    PyObject *out = PyUnicode_FromString(buf);
    free(buf);
    return out;
}

static PyObject *Target_write_cstr(Target *self, PyObject *args) {
    unsigned long addr; const char *s;
    if (!PyArg_ParseTuple(args, "ks", &addr, &s)) return NULL;
    size_t n = strlen(s) + 1;
    if (!write_mem(self->pid, addr, s, n)) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    Py_RETURN_NONE;
}

static PyObject *Target_read_ptr(Target *self, PyObject *args) {
    unsigned long addr;
    if (!PyArg_ParseTuple(args, "k", &addr)) return NULL;
    return read_typed(self->pid, addr, VT_PTR);
}

static PyObject *Target_follow(Target *self, PyObject *args) {
    unsigned long addr; PyObject *offsets;
    if (!PyArg_ParseTuple(args, "kO", &addr, &offsets)) return NULL;
    PyObject *seq = PySequence_Fast(offsets, "offsets must be a sequence");
    if (!seq) return NULL;
    Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
        long long off = PyLong_AsLongLong(item);
        if (PyErr_Occurred()) { Py_DECREF(seq); return NULL; }
        uint64_t p;
        if (!read_mem(self->pid, addr, &p, 8)) {
            Py_DECREF(seq); PyErr_SetFromErrno(PyExc_OSError); return NULL;
        }
        addr = (unsigned long)(p + (unsigned long)off);
    }
    Py_DECREF(seq);
    return PyLong_FromUnsignedLong(addr);
}

/* ==================== call: simple & struct ==================== */

static PyObject *Target_call(Target *self, PyObject *args, PyObject *kw) {
    const char *name;
    PyObject *arg_tuple = NULL;
    const char *ret_type = "i32";
    static char *kwlist[] = {"name", "args", "ret", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "s|Os",
                                     kwlist, &name, &arg_tuple, &ret_type)) return NULL;

    unsigned long addr = parse_addr_or_symbol(self, name);
    if (!addr) { PyErr_Format(PyExc_KeyError, "symbol '%s' not found", name); return NULL; }

    CallRegs r = {0};
    if (arg_tuple && arg_tuple != Py_None) {
        PyObject *seq = PySequence_Fast(arg_tuple, "args must be a sequence");
        if (!seq) return NULL;
        Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
        for (Py_ssize_t i = 0; i < n; i++) {
            PyObject *a = PySequence_Fast_GET_ITEM(seq, i);
            if (PyFloat_Check(a)) {
                if (r.n_sse >= 8) { Py_DECREF(seq); PyErr_SetString(PyExc_ValueError, "too many float args"); return NULL; }
                r.sse[r.n_sse][0] = (float)PyFloat_AsDouble(a);
                r.n_sse++;
            } else if (PyLong_Check(a)) {
                if (r.n_int >= 6) { Py_DECREF(seq); PyErr_SetString(PyExc_ValueError, "too many int args"); return NULL; }
                r.ints[r.n_int++] = (unsigned long)PyLong_AsLongLong(a);
            } else {
                Py_DECREF(seq);
                PyErr_SetString(PyExc_TypeError, "args must be int or float");
                return NULL;
            }
        }
        Py_DECREF(seq);
    }

    enum valtype rt;
    if (!parse_type(ret_type, &rt)) { PyErr_Format(PyExc_ValueError, "unknown ret type '%s'", ret_type); return NULL; }
    int want_float = (rt == VT_F32 || rt == VT_F64);
    if (rt == VT_F64) r.ret_is_double = 1;
    double fret = 0;
    long result = remote_call_typed(self->pid, addr, &r, want_float ? &fret : NULL);
    if (result == -1 && !want_float) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    if (want_float) return PyFloat_FromDouble(fret);
    return PyLong_FromLong(result);
}

static int unpack_arg(PyObject *a, CallRegs *r) {
    if (PyFloat_Check(a)) {
        if (r->n_sse >= 8) return -1;
        r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(a);
        r->n_sse++;
        return 0;
    }
    if (PyLong_Check(a)) {
        if (r->n_int >= 6) return -1;
        r->ints[r->n_int++] = (unsigned long)PyLong_AsLongLong(a);
        return 0;
    }
    if (PyTuple_Check(a)) {
        Py_ssize_t n = PyTuple_GET_SIZE(a);
        if (n < 1) return -1;
        PyObject *tag = PyTuple_GET_ITEM(a, 0);
        if (!PyUnicode_Check(tag)) return -1;
        const char *t = PyUnicode_AsUTF8(tag);

        if (!strcmp(t, "i")) {
            if (r->n_int >= 6) return -1;
            r->ints[r->n_int++] = (unsigned long)PyLong_AsLongLong(PyTuple_GET_ITEM(a, 1));
            return 0;
        }
        if (!strcmp(t, "f")) {
            if (r->n_sse >= 8) return -1;
            r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 1));
            r->n_sse++;
            return 0;
        }
        if (!strcmp(t, "v2")) {
            if (r->n_sse >= 8) return -1;
            r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 1));
            r->sse[r->n_sse][1] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 2));
            r->n_sse++;
            return 0;
        }
        if (!strcmp(t, "v3")) {
            if (r->n_sse + 2 > 8) return -1;
            r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 1));
            r->sse[r->n_sse][1] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 2));
            r->n_sse++;
            r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 3));
            r->n_sse++;
            return 0;
        }
        if (!strcmp(t, "v4")) {
            if (r->n_sse + 2 > 8) return -1;
            r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 1));
            r->sse[r->n_sse][1] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 2));
            r->n_sse++;
            r->sse[r->n_sse][0] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 3));
            r->sse[r->n_sse][1] = (float)PyFloat_AsDouble(PyTuple_GET_ITEM(a, 4));
            r->n_sse++;
            return 0;
        }
        return -1;
    }
    return -1;
}

static PyObject *Target_call_struct(Target *self, PyObject *args, PyObject *kw) {
    const char *name;
    PyObject *arg_tuple = NULL;
    const char *ret_type = "i32";
    static char *kwlist[] = {"name", "args", "ret", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "s|Os",
                                     kwlist, &name, &arg_tuple, &ret_type)) return NULL;

    unsigned long addr = parse_addr_or_symbol(self, name);
    if (!addr) { PyErr_Format(PyExc_KeyError, "symbol '%s' not found", name); return NULL; }

    CallRegs r = {0};
    if (arg_tuple && arg_tuple != Py_None) {
        PyObject *seq = PySequence_Fast(arg_tuple, "args must be a sequence");
        if (!seq) return NULL;
        Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
        for (Py_ssize_t i = 0; i < n; i++) {
            PyObject *a = PySequence_Fast_GET_ITEM(seq, i);
            if (unpack_arg(a, &r) != 0) {
                Py_DECREF(seq);
                PyErr_Format(PyExc_ValueError, "arg %zd couldn't be packed", i);
                return NULL;
            }
        }
        Py_DECREF(seq);
    }

    enum valtype rt;
    if (!parse_type(ret_type, &rt)) { PyErr_Format(PyExc_ValueError, "unknown ret type '%s'", ret_type); return NULL; }
    int want_float = (rt == VT_F32 || rt == VT_F64);
    if (rt == VT_F64) r.ret_is_double = 1;
    double fret = 0;
    long result = remote_call_typed(self->pid, addr, &r, want_float ? &fret : NULL);
    if (result == -1 && !want_float) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    if (want_float) return PyFloat_FromDouble(fret);
    return PyLong_FromLong(result);
}

/* ==================== hooks ==================== */

static unsigned long alloc_target_rwx(Target *self, size_t size) {
    unsigned long mmap_addr = find_libc_symbol(self, "mmap");
    if (!mmap_addr) return 0;
    CallRegs r = {0};
    r.n_int = 6;
    r.ints[0] = 0;
    r.ints[1] = (unsigned long)size;
    r.ints[2] = 7;
    r.ints[3] = 0x22;
    r.ints[4] = (unsigned long)-1;
    r.ints[5] = 0;
    long result = remote_call_typed(self->pid, mmap_addr, &r, NULL);
    if (result < 0) return 0;
    return (unsigned long)result;
}

static void build_abs_jmp(unsigned char out[14], unsigned long target) {
    out[0] = 0xFF; out[1] = 0x25;
    out[2] = out[3] = out[4] = out[5] = 0;
    memcpy(out + 6, &target, 8);
}

static PyObject *Target_hook(Target *self, PyObject *args) {
    const char *sym, *repl;
    if (!PyArg_ParseTuple(args, "ss", &sym, &repl)) return NULL;

    unsigned long src = target_resolve(self, sym);
    if (!src) { PyErr_Format(PyExc_KeyError, "symbol '%s' not found", sym); return NULL; }
    unsigned long dst = parse_addr_or_symbol(self, repl);
    if (!dst) { PyErr_Format(PyExc_KeyError, "replacement '%s' not found", repl); return NULL; }

    for (int i = 0; i < self->hook_n; i++)
        if (self->hooks[i].active && self->hooks[i].addr == src) {
            PyErr_Format(PyExc_RuntimeError, "'%s' already hooked", sym); return NULL;
        }
    if (self->hook_n >= HOOK_MAX) { PyErr_SetString(PyExc_RuntimeError, "hook table full"); return NULL; }

    pid_t tids[256];
    int n_tids = get_threads(self->pid, tids, 256);
    if (n_tids == 0) { tids[0] = self->pid; n_tids = 1; }
    int mask[256];
    if (ptrace_attach_all(tids, n_tids, mask) == 0) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }

    HookEntry *h = &self->hooks[self->hook_n];
    memset(h, 0, sizeof(*h));
    strncpy(h->name, sym, 127);
    h->addr = src;
    h->replacement = dst;
    h->prologue_size = 14;
    h->saved_len = 14;

    if (ptrace_peek_bytes(self->pid, src, h->saved, 14) < 0) {
        ptrace_detach_all(tids, n_tids, mask);
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }

    unsigned char patch[14];
    build_abs_jmp(patch, dst);
    if (ptrace_poke_bytes(self->pid, src, patch, 14) < 0) {
        ptrace_detach_all(tids, n_tids, mask);
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }

    ptrace_detach_all(tids, n_tids, mask);
    h->active = 1;
    self->hook_n++;
    return Py_BuildValue("(kk)", src, dst);
}

static PyObject *Target_hook_inline(Target *self, PyObject *args, PyObject *kw) {
    const char *sym, *repl;
    int prologue_size = 16;
    static char *kwlist[] = {"symbol", "replacement", "prologue", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "ss|i", kwlist,
                                     &sym, &repl, &prologue_size)) return NULL;

    if (prologue_size < 14) { PyErr_SetString(PyExc_ValueError, "prologue must be >= 14"); return NULL; }
    if (prologue_size > HOOK_SAVE_MAX - 14) { PyErr_Format(PyExc_ValueError, "prologue max %d", HOOK_SAVE_MAX - 14); return NULL; }

    unsigned long src = target_resolve(self, sym);
    if (!src) { PyErr_Format(PyExc_KeyError, "symbol '%s' not found", sym); return NULL; }
    unsigned long dst = parse_addr_or_symbol(self, repl);
    if (!dst) { PyErr_Format(PyExc_KeyError, "replacement '%s' not found", repl); return NULL; }

    for (int i = 0; i < self->hook_n; i++)
        if (self->hooks[i].active && self->hooks[i].addr == src) {
            PyErr_Format(PyExc_RuntimeError, "'%s' already hooked", sym); return NULL;
        }
    if (self->hook_n >= HOOK_MAX) { PyErr_SetString(PyExc_RuntimeError, "hook table full"); return NULL; }

    unsigned long tramp = alloc_target_rwx(self, 4096);
    if (!tramp) { PyErr_SetString(PyExc_RuntimeError, "failed to mmap trampoline"); return NULL; }

    unsigned char orig[HOOK_SAVE_MAX];
    if (!read_mem(self->pid, src, orig, prologue_size)) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }

    unsigned char tramp_code[HOOK_SAVE_MAX + 14];
    memcpy(tramp_code, orig, prologue_size);
    build_abs_jmp(tramp_code + prologue_size, src + prologue_size);
    size_t tramp_total = prologue_size + 14;

    if (!write_mem(self->pid, tramp, tramp_code, tramp_total)) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }

    pid_t tids[256];
    int n_tids = get_threads(self->pid, tids, 256);
    if (n_tids == 0) { tids[0] = self->pid; n_tids = 1; }
    int mask[256];
    if (ptrace_attach_all(tids, n_tids, mask) == 0) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }

    unsigned char patch[HOOK_SAVE_MAX];
    build_abs_jmp(patch, dst);
    for (int i = 14; i < prologue_size; i++) patch[i] = 0x90;
    if (ptrace_poke_bytes(self->pid, src, patch, prologue_size) < 0) {
        ptrace_detach_all(tids, n_tids, mask);
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }
    ptrace_detach_all(tids, n_tids, mask);

    HookEntry *h = &self->hooks[self->hook_n];
    memset(h, 0, sizeof(*h));
    strncpy(h->name, sym, 127);
    h->addr = src;
    h->replacement = dst;
    h->trampoline = tramp;
    h->prologue_size = prologue_size;
    memcpy(h->saved, orig, prologue_size);
    h->saved_len = prologue_size;
    h->active = 1;
    self->hook_n++;
    return PyLong_FromUnsignedLong(tramp);
}

static PyObject *Target_unhook(Target *self, PyObject *args) {
    const char *sym;
    if (!PyArg_ParseTuple(args, "s", &sym)) return NULL;

    HookEntry *found = NULL;
    for (int i = 0; i < self->hook_n; i++)
        if (self->hooks[i].active && strcmp(self->hooks[i].name, sym) == 0) {
            found = &self->hooks[i]; break;
        }
    if (!found) { PyErr_Format(PyExc_KeyError, "no active hook for '%s'", sym); return NULL; }

    pid_t tids[256];
    int n_tids = get_threads(self->pid, tids, 256);
    if (n_tids == 0) { tids[0] = self->pid; n_tids = 1; }
    int mask[256];
    if (ptrace_attach_all(tids, n_tids, mask) == 0) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    if (ptrace_poke_bytes(self->pid, found->addr, found->saved, found->saved_len) < 0) {
        ptrace_detach_all(tids, n_tids, mask);
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }
    ptrace_detach_all(tids, n_tids, mask);
    found->active = 0;
    Py_RETURN_TRUE;
}

static PyObject *Target_patch(Target *self, PyObject *args) {
    unsigned long addr;
    Py_buffer b;
    if (!PyArg_ParseTuple(args, "ky*", &addr, &b)) return NULL;

    pid_t tids[256];
    int n_tids = get_threads(self->pid, tids, 256);
    if (n_tids == 0) { tids[0] = self->pid; n_tids = 1; }
    int mask[256];
    if (ptrace_attach_all(tids, n_tids, mask) == 0) {
        PyBuffer_Release(&b);
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }
    int ok = ptrace_poke_bytes(self->pid, addr, b.buf, b.len);
    ptrace_detach_all(tids, n_tids, mask);
    PyBuffer_Release(&b);
    if (ok < 0) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    Py_RETURN_NONE;
}

static PyObject *Target_hooks(Target *self, PyObject *noargs) {
    PyObject *list = PyList_New(0);
    for (int i = 0; i < self->hook_n; i++) {
        if (!self->hooks[i].active) continue;
        PyObject *d = PyDict_New();
        PyDict_SetItemString(d, "name",        PyUnicode_FromString(self->hooks[i].name));
        PyDict_SetItemString(d, "addr",        PyLong_FromUnsignedLong(self->hooks[i].addr));
        PyDict_SetItemString(d, "replacement", PyLong_FromUnsignedLong(self->hooks[i].replacement));
        PyDict_SetItemString(d, "trampoline",  PyLong_FromUnsignedLong(self->hooks[i].trampoline));
        PyDict_SetItemString(d, "prologue",    PyLong_FromLong(self->hooks[i].prologue_size));
        PyList_Append(list, d);
        Py_DECREF(d);
    }
    return list;
}

/* ==================== scanner ==================== */

static PyObject *do_scan(Target *self, const char *pattern_str,
                         const char *module_filter, int first_only) {
    char err[128];
    Pattern *pat = parse_pattern(pattern_str, err, sizeof(err));
    if (!pat) { PyErr_SetString(PyExc_ValueError, err); return NULL; }

    PyObject *results = first_only ? NULL : PyList_New(0);
    int found_first = 0;
    unsigned long first_addr = 0;

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", self->pid);
    FILE *f = fopen(mpath, "r");
    if (!f) { free(pat->bytes); free(pat->mask); free(pat); PyErr_SetFromErrno(PyExc_OSError); return NULL; }

    const size_t CHUNK = 4 * 1024 * 1024;
    uint8_t *buf = malloc(CHUNK + pat->len);
    if (!buf) { fclose(f); free(pat->bytes); free(pat->mask); free(pat); return PyErr_NoMemory(); }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long s, e, off, inode;
        char perms[8], dev[16], name[512] = {0};
        int parsed = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511s",
                            &s, &e, perms, &off, dev, &inode, name);
        if (parsed < 2) continue;
        if (perms[0] != 'r') continue;

        if (module_filter && module_filter[0]) {
            if (parsed < 6) continue;
            const char *slash = strrchr(name, '/');
            const char *base = slash ? slash + 1 : name;
            if (strcmp(name, module_filter) != 0 && strcmp(base, module_filter) != 0) continue;
        }

        unsigned long addr = s, remaining = e - s;
        while (remaining > 0) {
            size_t to_read = remaining > CHUNK ? CHUNK : remaining;
            size_t read_size = to_read;
            if (remaining > to_read) read_size += pat->len - 1;
            if (read_size > CHUNK + pat->len) read_size = CHUNK + pat->len;

            if (!read_mem(self->pid, addr, buf, read_size)) break;

            if (read_size >= pat->len) {
                for (size_t i = 0; i + pat->len <= read_size; i++) {
                    if (!pattern_match(pat, buf + i)) continue;
                    unsigned long hit = addr + i;
                    if (first_only) { first_addr = hit; found_first = 1; goto done; }
                    PyObject *v = PyLong_FromUnsignedLong(hit);
                    PyList_Append(results, v);
                    Py_DECREF(v);
                }
            }
            if (to_read >= remaining) break;
            addr += to_read;
            remaining -= to_read;
        }
    }
done:
    fclose(f);
    free(buf);
    free(pat->bytes);
    free(pat->mask);
    free(pat);

    if (first_only) {
        if (!found_first) Py_RETURN_NONE;
        return PyLong_FromUnsignedLong(first_addr);
    }
    return results;
}

static PyObject *Target_scan(Target *self, PyObject *args, PyObject *kw) {
    const char *pat;
    const char *mod = NULL;
    static char *kwlist[] = {"pattern", "module", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "s|z", kwlist, &pat, &mod)) return NULL;
    return do_scan(self, pat, mod, 1);
}

static PyObject *Target_scan_all(Target *self, PyObject *args, PyObject *kw) {
    const char *pat;
    const char *mod = NULL;
    static char *kwlist[] = {"pattern", "module", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "s|z", kwlist, &pat, &mod)) return NULL;
    return do_scan(self, pat, mod, 0);
}

/* ==================== modules / regions ==================== */

static PyObject *Module_new(pid_t pid, const ModuleInfo *mi);

static PyObject *Target_modules(Target *self, PyObject *noargs) {
    ensure_modules(self);
    PyObject *list = PyList_New(0);
    for (int i = 0; i < self->module_count; i++) {
        PyObject *m = Module_new(self->pid, &self->modules[i]);
        if (!m) { Py_DECREF(list); return NULL; }
        PyList_Append(list, m);
        Py_DECREF(m);
    }
    return list;
}

static PyObject *Target_module(Target *self, PyObject *args) {
    const char *name;
    if (!PyArg_ParseTuple(args, "s", &name)) return NULL;
    ensure_modules(self);
    for (int i = 0; i < self->module_count; i++) {
        if (strcmp(self->modules[i].name, name) == 0 ||
            strcmp(self->modules[i].path, name) == 0) {
            return Module_new(self->pid, &self->modules[i]);
        }
    }
    PyErr_Format(PyExc_KeyError, "module '%s' not loaded", name);
    return NULL;
}

static PyObject *Target_regions(Target *self, PyObject *noargs) {
    RegionInfo *rs = malloc(sizeof(RegionInfo) * 2048);
    if (!rs) return PyErr_NoMemory();
    int n = enumerate_regions(self->pid, rs, 2048);
    PyObject *list = PyList_New(0);
    for (int i = 0; i < n; i++) {
        PyObject *d = PyDict_New();
        PyDict_SetItemString(d, "start", PyLong_FromUnsignedLong(rs[i].start));
        PyDict_SetItemString(d, "end",   PyLong_FromUnsignedLong(rs[i].end));
        PyDict_SetItemString(d, "size",  PyLong_FromUnsignedLong(rs[i].end - rs[i].start));
        PyDict_SetItemString(d, "perms", PyUnicode_FromString(rs[i].perms));
        PyDict_SetItemString(d, "path",  PyUnicode_FromString(rs[i].path));
        PyList_Append(list, d);
        Py_DECREF(d);
    }
    free(rs);
    return list;
}

/* ==================== properties / method table ==================== */

static PyObject *Target_get_pid (Target *self, void *c) { return PyLong_FromLong(self->pid); }
static PyObject *Target_get_base(Target *self, void *c) { return PyLong_FromUnsignedLong(self->base); }
static PyObject *Target_get_exe (Target *self, void *c) { return PyUnicode_FromString(self->exe_path); }

static PyGetSetDef Target_getset[] = {
    {"pid",  (getter)Target_get_pid,  NULL, "target PID", NULL},
    {"base", (getter)Target_get_base, NULL, "ELF load base", NULL},
    {"exe",  (getter)Target_get_exe,  NULL, "target exe path", NULL},
    {NULL}
};

static PyMethodDef Target_methods[] = {
    {"find",        (PyCFunction)Target_find,        METH_VARARGS,                    "find(symbol) -> addr"},
    {"read",        (PyCFunction)Target_read,        METH_VARARGS|METH_KEYWORDS,      "read(addr, type='i32')"},
    {"write",       (PyCFunction)Target_write,       METH_VARARGS|METH_KEYWORDS,      "write(addr, value, type='i32')"},
    {"read_bytes",  (PyCFunction)Target_read_bytes,  METH_VARARGS,                    "read_bytes(addr, n)"},
    {"write_bytes", (PyCFunction)Target_write_bytes, METH_VARARGS,                    "write_bytes(addr, data)"},
    {"read_cstr",   (PyCFunction)Target_read_cstr,   METH_VARARGS,                    "read_cstr(addr, maxlen=256)"},
    {"write_cstr",  (PyCFunction)Target_write_cstr,  METH_VARARGS,                    "write_cstr(addr, s)"},
    {"read_ptr",    (PyCFunction)Target_read_ptr,    METH_VARARGS,                    "read_ptr(addr)"},
    {"follow",      (PyCFunction)Target_follow,      METH_VARARGS,                    "follow(addr, [offsets])"},
    {"scan",        (PyCFunction)Target_scan,        METH_VARARGS|METH_KEYWORDS,      "scan(pattern, module=None)"},
    {"scan_all",    (PyCFunction)Target_scan_all,    METH_VARARGS|METH_KEYWORDS,      "scan_all(pattern, module=None)"},
    {"modules",     (PyCFunction)Target_modules,     METH_NOARGS,                     "modules()"},
    {"module",      (PyCFunction)Target_module,      METH_VARARGS,                    "module(name)"},
    {"regions",     (PyCFunction)Target_regions,     METH_NOARGS,                     "regions()"},
    {"hook",        (PyCFunction)Target_hook,        METH_VARARGS,                    "hook(symbol, replacement)"},
    {"hook_inline", (PyCFunction)Target_hook_inline, METH_VARARGS|METH_KEYWORDS,      "hook_inline(symbol, replacement, prologue=16)"},
    {"unhook",      (PyCFunction)Target_unhook,      METH_VARARGS,                    "unhook(symbol)"},
    {"patch",       (PyCFunction)Target_patch,       METH_VARARGS,                    "patch(addr, bytes)"},
    {"hooks",       (PyCFunction)Target_hooks,       METH_NOARGS,                     "hooks()"},
    {"call",        (PyCFunction)Target_call,        METH_VARARGS|METH_KEYWORDS,      "call(name, args=(), ret='i32')"},
    {"call_struct", (PyCFunction)Target_call_struct, METH_VARARGS|METH_KEYWORDS,      "call_struct(name, args, ret='i32')"},
    {NULL}
};

static PyTypeObject TargetType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "pokex.Target",
    .tp_basicsize = sizeof(Target),
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "Live memory view of a running process",
    .tp_methods   = Target_methods,
    .tp_getset    = Target_getset,
    .tp_getattro  = Target_getattro,
    .tp_setattro  = Target_setattro,
};

/* ==================== Module ==================== */

static PyObject *Module_symbol(Module *self, PyObject *args) {
    const char *name;
    if (!PyArg_ParseTuple(args, "s", &name)) return NULL;
    unsigned long a = resolve_in_module(self->pid, self->path, self->base, name);
    if (!a) { PyErr_Format(PyExc_KeyError, "symbol '%s' not found in %s", name, self->name); return NULL; }
    return PyLong_FromUnsignedLong(a);
}

static PyObject *Module_get_name(Module *self, void *c) { return PyUnicode_FromString(self->name); }
static PyObject *Module_get_path(Module *self, void *c) { return PyUnicode_FromString(self->path); }
static PyObject *Module_get_base(Module *self, void *c) { return PyLong_FromUnsignedLong(self->base); }
static PyObject *Module_get_size(Module *self, void *c) { return PyLong_FromUnsignedLong(self->size); }
static PyObject *Module_get_end (Module *self, void *c) { return PyLong_FromUnsignedLong(self->base + self->size); }

static PyGetSetDef Module_getset[] = {
    {"name", (getter)Module_get_name, NULL, "basename",    NULL},
    {"path", (getter)Module_get_path, NULL, "full path",   NULL},
    {"base", (getter)Module_get_base, NULL, "load base",   NULL},
    {"size", (getter)Module_get_size, NULL, "total size",  NULL},
    {"end",  (getter)Module_get_end,  NULL, "base + size", NULL},
    {NULL}
};

static PyMethodDef Module_methods[] = {
    {"symbol", (PyCFunction)Module_symbol, METH_VARARGS, "symbol(name)"},
    {NULL}
};

static PyTypeObject ModuleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "pokex.Module",
    .tp_basicsize = sizeof(Module),
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "A loaded module",
    .tp_methods   = Module_methods,
    .tp_getset    = Module_getset,
};

static PyObject *Module_new(pid_t pid, const ModuleInfo *mi) {
    Module *m = (Module *)ModuleType.tp_alloc(&ModuleType, 0);
    if (!m) return NULL;
    m->pid = pid;
    strncpy(m->path, mi->path, 511); m->path[511] = 0;
    strncpy(m->name, mi->name, 255); m->name[255] = 0;
    m->base = mi->base;
    m->size = mi->end - mi->base;
    return (PyObject *)m;
}

/* ==================== attach() ==================== */

static PyObject *py_attach(PyObject *mod, PyObject *args) {
    pid_t pid;
    if (!PyArg_ParseTuple(args, "i", &pid)) return NULL;
    if (pid <= 0) { PyErr_SetString(PyExc_ValueError, "bad pid"); return NULL; }

    char link[64], exe_path[512];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t l = readlink(link, exe_path, sizeof(exe_path) - 1);
    if (l < 0) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    exe_path[l] = 0;

    int fd = open(link, O_RDONLY);
    if (fd < 0) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) {
        close(fd); PyErr_SetString(PyExc_OSError, "cannot read ELF header"); return NULL;
    }
    int is_pie = (eh.e_type == ET_DYN);
    close(fd);

    unsigned long base = 0;
    if (is_pie) {
        ModuleInfo mods[MAX_MODULES];
        int n = enumerate_modules(pid, mods, MAX_MODULES);
        for (int i = 0; i < n; i++)
            if (strcmp(mods[i].path, exe_path) == 0) { base = mods[i].base; break; }
    }

    Target *t = (Target *)TargetType.tp_alloc(&TargetType, 0);
    if (!t) return NULL;
    t->pid = pid;
    strncpy(t->exe_path, exe_path, sizeof(t->exe_path) - 1);
    t->exe_path[sizeof(t->exe_path) - 1] = 0;
    t->base = base;
    t->is_pie = is_pie;
    t->cache_n = 0;
    t->modules_loaded = 0;
    t->hook_n = 0;
    t->hooks = calloc(HOOK_MAX, sizeof(HookEntry));
    if (!t->hooks) { Py_DECREF(t); return PyErr_NoMemory(); }
    return (PyObject *)t;
}

static PyMethodDef PokexMethods[] = {
    {"attach", py_attach, METH_VARARGS, "attach(pid) -> Target"},
    {NULL}
};

static struct PyModuleDef PokexModule = {
    PyModuleDef_HEAD_INIT, "pokex", "runtime memory patcher", -1, PokexMethods,
};

/* ==================== banner ==================== */

#define C1  "\033[36m"
#define C2  "\033[35m"
#define C3  "\033[33m"
#define DIM "\033[2m"
#define R   "\033[0m"

static void print_banner(pid_t pid, const char *exe, int is_pie, unsigned long base) {
    printf("\n");
    printf(C1 "    ____       __          \n");
    printf(C1 "   / __ \\____  / /_____     \n");
    printf(C1 "  / /_/ / __ \\/ //_/ _ \\    \n");
    printf(C1 " / ____/ /_/ / ,< /  __/    \n");
    printf(C1 "/_/    \\____/_/|_|\\___/     " C2 "v0.4.4\n" R);
    printf(DIM "   runtime memory patcher for linux x86-64\n" R);
    printf("\n");
    printf(C3 "  target :" R " %s\n", exe);
    printf(C3 "  pid    :" R " %d\n", pid);
    printf(C3 "  pie    :" R " %s\n", is_pie ? "yes" : "no");
    printf(C3 "  base   :" R " 0x%lx\n", base);
    printf("\n");
}

/* ==================== main ==================== */

static char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); free(buf); return NULL; }
    buf[sz] = 0; fclose(f);
    if (out_len) *out_len = sz;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <pid> <script.py> [--no-banner]\n", argv[0]); return 1; }
    pid_t pid = (pid_t)atoi(argv[1]);
    if (pid <= 0) { fprintf(stderr, "bad pid\n"); return 1; }

    int show_banner = 1;
    for (int i = 3; i < argc; i++)
        if (strcmp(argv[i], "--no-banner") == 0) show_banner = 0;

    Py_Initialize();
       

  PyRun_SimpleString(
        "import sys, os\n"
        "for p in (\n"
        "    '/usr/local/share/pokex',\n"
        "    '/usr/share/pokex',\n"
        "    os.path.expanduser('~/.local/share/pokex'),\n"
        "    './lib',\n"
        "):\n"
        "    if os.path.isdir(p) and p not in sys.path:\n"
        "        sys.path.insert(0, p)\n"
    );
    
    if (PyType_Ready(&TargetType) < 0) { PyErr_Print(); return 1; }
    if (PyType_Ready(&ModuleType) < 0) { PyErr_Print(); return 1; }

    PyObject *tobj = py_attach(NULL, Py_BuildValue("(i)", pid));
    if (!tobj) { PyErr_Print(); return 1; }
    Target *t = (Target *)tobj;

    if (show_banner) print_banner(t->pid, t->exe_path, t->is_pie, t->base);

    long src_len;
    char *src = read_file(argv[2], &src_len);
    if (!src) { perror(argv[2]); return 1; }
    PyObject *globals = PyDict_New();
    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());

    PyObject *name = PyUnicode_FromString("__main__");
    PyDict_SetItemString(globals, "__name__", name);
    Py_DECREF(name);

    PyDict_SetItemString(globals, "target", tobj);

    /* Also publish `target` into builtins so imported modules can see it */
    PyObject *builtins = PyImport_ImportModule("builtins");
    if (builtins) {
        PyObject_SetAttrString(builtins, "target", tobj);
        Py_DECREF(builtins);
    }

    PyObject *mod = PyModule_Create(&PokexModule);
    PyDict_SetItemString(globals, "pokex", mod);
    Py_DECREF(mod);

    PyObject *res = PyRun_String(src, Py_file_input, globals, globals);
    if (!res) PyErr_Print();
    else Py_DECREF(res);
    free(src);
    Py_Finalize();
    return 0;
}
