"""metrics.py — Muestreo de rendimiento del equipo (CPU, RAM, disco, red).

Alimenta el "latido" de telemetria en vivo que el panel dibuja estilo Task
Manager. Prefiere `psutil` si esta disponible (mas preciso, incluye red); si no,
cae a la API de Windows por `ctypes`, para no imponer dependencias al agente.

Todas las funciones devuelven porcentajes 0-100, salvo `red` que va en Mbps.
"""
from __future__ import annotations

import time
import ctypes

# Estado entre muestras (para tasas: CPU y red se calculan por diferencia).
_last_net = {"t": 0.0, "bytes": 0}
_last_cpu = None  # (idle, kernel, user)


# ── Ruta preferida: psutil ───────────────────────────────────────────────────

def _sample_psutil() -> dict:
    import psutil
    cpu = psutil.cpu_percent(interval=None)      # % desde la ultima llamada
    ram = psutil.virtual_memory().percent
    try:
        disco = psutil.disk_usage("C:\\").percent
    except Exception:
        disco = psutil.disk_usage("/").percent
    return {"cpu": cpu, "ram": ram, "disco": disco, "red": _net_mbps_psutil(psutil)}


def _net_mbps_psutil(psutil) -> float:
    global _last_net
    now = time.time()
    io = psutil.net_io_counters()
    total = io.bytes_sent + io.bytes_recv
    if _last_net["t"] == 0:
        _last_net = {"t": now, "bytes": total}
        return 0.0
    dt = now - _last_net["t"]
    db = total - _last_net["bytes"]
    _last_net = {"t": now, "bytes": total}
    if dt <= 0 or db < 0:
        return 0.0
    return (db * 8.0 / 1_000_000.0) / dt


# ── Respaldo: API de Windows por ctypes (CPU + RAM + disco) ───────────────────

class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def _ram_ctypes() -> float:
    m = _MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return float(m.dwMemoryLoad)


def _read_system_times():
    # FILETIME (2x DWORD) equivale en memoria a un c_ulonglong little-endian.
    idle = ctypes.c_ulonglong(0); kernel = ctypes.c_ulonglong(0); user = ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
    return idle.value, kernel.value, user.value  # kernel INCLUYE el tiempo idle


def _cpu_ctypes() -> float:
    global _last_cpu
    cur = _read_system_times()
    if _last_cpu is None:
        _last_cpu = cur
        time.sleep(0.25)
        cur = _read_system_times()
    di = cur[0] - _last_cpu[0]
    dk = cur[1] - _last_cpu[1]
    du = cur[2] - _last_cpu[2]
    _last_cpu = cur
    total = dk + du
    if total <= 0:
        return 0.0
    busy = total - di
    return max(0.0, min(100.0, 100.0 * busy / total))


def _disk_ctypes() -> float:
    free = ctypes.c_ulonglong(0); total = ctypes.c_ulonglong(0)
    ok = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p("C:\\"), None, ctypes.byref(total), ctypes.byref(free))
    if not ok or total.value == 0:
        return 0.0
    return 100.0 * (total.value - free.value) / total.value


def _sample_ctypes() -> dict:
    return {"cpu": _cpu_ctypes(), "ram": _ram_ctypes(), "disco": _disk_ctypes(), "red": 0.0}


# ── API publica ──────────────────────────────────────────────────────────────

def sample() -> dict:
    """Devuelve {cpu, ram, disco, red}. Nunca lanza: ante error, ceros."""
    try:
        d = _sample_psutil()
    except Exception:
        try:
            d = _sample_ctypes()
        except Exception:
            d = {"cpu": 0.0, "ram": 0.0, "disco": 0.0, "red": 0.0}
    return {k: round(float(v), 2) for k, v in d.items()}
