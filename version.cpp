#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wininet.h>

#pragma function(memcpy, memset)
extern "C" {
    void* memcpy(void* d, const void* s, size_t n) {
        BYTE* dd = (BYTE*)d; const BYTE* ss = (const BYTE*)s;
        while (n--) *dd++ = *ss++;
        return d;
    }
    void* memset(void* d, int c, size_t n) {
        BYTE* dd = (BYTE*)d;
        while (n--) *dd++ = (BYTE)c;
        return d;
    }
}
static char* _strstr(const char* h, const char* n) {
    if (!*n) return (char*)h;
    for (; *h; h++) {
        const char* a = h, *b = n;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return (char*)h;
    }
    return NULL;
}
static size_t _strlen(const char* s) { const char* p = s; while (*p) p++; return p - s; }
static char* _strcat(char* d, const char* s) { char* p = d; while (*p) p++; while ((*p++ = *s++)); return d; }
#define strstr _strstr
#define strlen _strlen
#define strcat _strcat

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")

static HMODULE g_realVersion = NULL;
static HMODULE g_selfMod = NULL;
static DWORD g_myPid = 0;
static HDESK g_defaultDesktop = NULL;
static volatile DWORD g_tk = 0;
static volatile DWORD g_tkh = 0;
static DWORD g_seed = 0;

#define TK_MAGIC   0xA7B3C1D9u
#define _TKH(v)    (((v) * 0x27D4EB2Du) ^ (((v) >> 16) * 0x85EBCA77u))
#define TK_INIT()  do { g_tk = TK_MAGIC ^ g_seed; g_tkh = _TKH(g_tk); } while(0)
#define TK_OK(k)   ((g_tk ^ g_seed ^ (k)) == (TK_MAGIC ^ (k)) && g_tkh == _TKH(g_tk))
#define TK_KILL()  do { LARGE_INTEGER _c; QueryPerformanceCounter(&_c); \
    g_tk = (DWORD)_c.LowPart; g_tkh = ~_TKH(g_tk); } while(0)

constexpr unsigned _MK(unsigned k, unsigned i) {
    k ^= i * 0x45D9F3Bu;
    k = ((k >> 16) ^ k) * 0x45D9F3Bu;
    k = ((k >> 16) ^ k) * 0x119Au;
    return k;
}

constexpr char _EB(char c, unsigned k) {
    unsigned char r = (unsigned char)c;
    r ^= (unsigned char)(k & 0xFF);
    r += (unsigned char)((k >> 8) & 0x3F);
    r ^= (unsigned char)((k >> 16) & 0xFF);
    return (char)r;
}

static char _DB(char c, unsigned k) {
    unsigned char r = (unsigned char)c;
    r ^= (unsigned char)((k >> 16) & 0xFF);
    r -= (unsigned char)((k >> 8) & 0x3F);
    r ^= (unsigned char)(k & 0xFF);
    return (char)r;
}

template<unsigned N>
struct XS {
    char d[N];
    unsigned k;
    constexpr XS(const char (&s)[N], unsigned key) : d{}, k(key) {
        for (unsigned i = 0; i < N; i++)
            d[i] = _EB(s[i], _MK(key, i));
    }
};

template<unsigned N>
static const char* _DX(char* out, const char (&enc)[N], unsigned key) {
    for (unsigned i = 0; i < N; i++)
        out[i] = _DB(enc[i], _MK(key, i));
    return out;
}

#define S(s) []() -> const char* { \
    constexpr unsigned _k = (__LINE__ * 0x8C35Eu) ^ (__COUNTER__ * 0x7331u + 0x51D3u); \
    static constexpr XS<sizeof(s)> _e(s, _k); \
    static char _b[sizeof(s)]; \
    static volatile bool _f = false; \
    if (!_f) { _DX(_b, _e.d, _k); _f = true; } \
    return _b; \
}()

static HMODULE LoadRealVersion()
{
    if (!g_realVersion)
    {
        char p[MAX_PATH];
        GetSystemDirectoryA(p, MAX_PATH);
        strcat(p, S("\\version.dll"));
        g_realVersion = LoadLibraryA(p);
    }
    return g_realVersion;
}

static FARPROC GetReal(const char* n)
{
    HMODULE m = LoadRealVersion();
    return m ? GetProcAddress(m, n) : NULL;
}

#define PXY(name, ret, conv, args, call) \
    typedef ret (conv* t_##name) args; \
    extern "C" ret conv proxy_##name args { \
        static t_##name r = NULL; \
        if (!r) r = (t_##name)GetReal(#name); \
        if (!r) return (ret)0; \
        return r call; \
    }

PXY(GetFileVersionInfoA, BOOL, WINAPI, (LPCSTR f,DWORD h,DWORD s,LPVOID d), (f,h,s,d))
PXY(GetFileVersionInfoW, BOOL, WINAPI, (LPCWSTR f,DWORD h,DWORD s,LPVOID d), (f,h,s,d))
PXY(GetFileVersionInfoSizeA, DWORD, WINAPI, (LPCSTR f,LPDWORD h), (f,h))
PXY(GetFileVersionInfoSizeW, DWORD, WINAPI, (LPCWSTR f,LPDWORD h), (f,h))
PXY(GetFileVersionInfoExA, BOOL, WINAPI, (DWORD fl,LPCSTR f,DWORD h,DWORD s,LPVOID d), (fl,f,h,s,d))
PXY(GetFileVersionInfoExW, BOOL, WINAPI, (DWORD fl,LPCWSTR f,DWORD h,DWORD s,LPVOID d), (fl,f,h,s,d))
PXY(GetFileVersionInfoSizeExA, DWORD, WINAPI, (DWORD fl,LPCSTR f,LPDWORD h), (fl,f,h))
PXY(GetFileVersionInfoSizeExW, DWORD, WINAPI, (DWORD fl,LPCWSTR f,LPDWORD h), (fl,f,h))
PXY(VerFindFileA, DWORD, WINAPI, (DWORD fl,LPCSTR a,LPCSTR b,LPCSTR c,LPSTR d,PUINT e,LPSTR f,PUINT g), (fl,a,b,c,d,e,f,g))
PXY(VerFindFileW, DWORD, WINAPI, (DWORD fl,LPCWSTR a,LPCWSTR b,LPCWSTR c,LPWSTR d,PUINT e,LPWSTR f,PUINT g), (fl,a,b,c,d,e,f,g))
PXY(VerInstallFileA, DWORD, WINAPI, (DWORD fl,LPCSTR a,LPCSTR b,LPCSTR c,LPCSTR d,LPCSTR e,LPSTR f,PUINT g), (fl,a,b,c,d,e,f,g))
PXY(VerInstallFileW, DWORD, WINAPI, (DWORD fl,LPCWSTR a,LPCWSTR b,LPCWSTR c,LPCWSTR d,LPCWSTR e,LPWSTR f,PUINT g), (fl,a,b,c,d,e,f,g))
PXY(VerLanguageNameA, DWORD, WINAPI, (DWORD l,LPSTR b,DWORD s), (l,b,s))
PXY(VerLanguageNameW, DWORD, WINAPI, (DWORD l,LPWSTR b,DWORD s), (l,b,s))
PXY(VerQueryValueA, BOOL, WINAPI, (LPCVOID bl,LPCSTR sub,LPVOID* buf,PUINT len), (bl,sub,buf,len))
PXY(VerQueryValueW, BOOL, WINAPI, (LPCVOID bl,LPCWSTR sub,LPVOID* buf,PUINT len), (bl,sub,buf,len))

#define TRAMPOLINE_SIZE 32
static BYTE* g_pool = NULL;
static int g_poolIdx = 0;

static BYTE* AllocTrampoline()
{
    if (!g_pool)
        g_pool = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!g_pool) return NULL;
    BYTE* t = g_pool + (g_poolIdx * TRAMPOLINE_SIZE);
    g_poolIdx++;
    return t;
}

static void FinalizePool()
{
    if (g_pool) { DWORD op; VirtualProtect(g_pool, 4096, PAGE_EXECUTE_READ, &op); }
}

static int GetInsnLen(BYTE* p)
{
    if (p[0] >= 0x50 && p[0] <= 0x5F) return 1;
    if (p[0] == 0x90 || p[0] == 0xCC || p[0] == 0xC3) return 1;
    if (p[0] == 0x8B && (p[1] & 0xC0) == 0xC0) return 2;
    if (p[0] == 0x33 && (p[1] & 0xC0) == 0xC0) return 2;
    if (p[0] == 0x6A || p[0] == 0xEB) return 2;
    if (p[0] == 0x8B && p[1] == 0xEC) return 2;
    if (p[0] == 0x8B && (p[1] & 0xC7) == 0x45) return 3;
    if (p[0] == 0x83 && (p[1] == 0xEC || p[1] == 0xE4)) return 3;
    if (p[0] == 0xC2) return 3;
    if (p[0] == 0x89 && (p[1] & 0xC7) == 0x45) return 3;
    if (p[0] == 0x89 && (p[1] & 0xC7) == 0x44) return 4;
    if (p[0] == 0xE9 || p[0] == 0xE8) return 5;
    if (p[0] >= 0xB8 && p[0] <= 0xBF) return 5;
    if (p[0] == 0x68) return 5;
    if (p[0] == 0x81 && p[1] == 0xEC) return 6;
    if (p[0] == 0xFF && p[1] == 0x25) return 6;
    if (p[0] == 0xC7 && p[1] == 0x45) return 7;
    return 1;
}

static int CalcCopyLen(BYTE* t, int min)
{
    int total = 0;
    while (total < min) { total += GetInsnLen(t + total); if (total > 16) break; }
    return total;
}

static bool DoHook(const char* mod, const char* func, void* detour, void** ppTramp)
{
    HMODULE hM = GetModuleHandleA(mod);
    if (!hM) return false;
    BYTE* target = (BYTE*)GetProcAddress(hM, func);
    if (!target) return false;

    int d = 0;
    while (target[0] == 0xE9 && d < 5) {
        target = target + 5 + *(DWORD*)(target + 1); d++;
    }
    if (target[0] == 0xFF && target[1] == 0x25)
        target = *(BYTE**)(*(DWORD*)(target + 2));

    BYTE* tramp = AllocTrampoline();
    if (!tramp) return false;

    int cl = CalcCopyLen(target, 5);

    if (target[0] == 0xE9 && cl == 5) {
        BYTE* jt = target + 5 + *(DWORD*)(target + 1);
        tramp[0] = 0xE9;
        *(DWORD*)(tramp + 1) = (DWORD)jt - (DWORD)(tramp + 5);
    } else {
        memcpy(tramp, target, cl);
        tramp[cl] = 0xE9;
        *(DWORD*)(tramp + cl + 1) = (DWORD)(target + cl) - (DWORD)(tramp + cl + 5);
    }

    *ppTramp = tramp;

    DWORD op;
    VirtualProtect(target, cl, PAGE_EXECUTE_READWRITE, &op);
    target[0] = 0xE9;
    *(DWORD*)(target + 1) = (DWORD)detour - (DWORD)(target + 5);
    for (int i = 5; i < cl; i++) target[i] = 0x90;
    VirtualProtect(target, cl, op, &op);
    FlushInstructionCache(GetCurrentProcess(), target, cl);
    return true;
}

static HWND FindLDB()
{
    struct C { DWORD pid; HWND r; };
    C c = { g_myPid, NULL };
    EnumWindows([](HWND hw, LPARAM lp) -> BOOL {
        C* x = (C*)lp; DWORD pid;
        GetWindowThreadProcessId(hw, &pid);
        if (pid == x->pid && IsWindowVisible(hw) && (GetWindowLongA(hw, GWL_STYLE) & WS_CAPTION))
            { x->r = hw; return FALSE; }
        return TRUE;
    }, (LPARAM)&c);
    return c.r;
}

typedef BOOL (WINAPI* fn_TP)(HANDLE,UINT);
static fn_TP o_TP = NULL;
BOOL WINAPI hk_TP(HANDLE h, UINT c) {
    if (!TK_OK(0x11u)) return o_TP(h, c);
    if (h == GetCurrentProcess() || h == (HANDLE)-1) return o_TP(h, c);
    DWORD p = GetProcessId(h);
    if (p == g_myPid || p == 0) return o_TP(h, c);
    return TRUE;
}

typedef LONG (NTAPI* fn_NTP)(HANDLE,LONG);
static fn_NTP o_NTP = NULL;
LONG NTAPI hk_NTP(HANDLE h, LONG s) {
    if (!TK_OK(0x22u)) return o_NTP(h, s);
    if (h == GetCurrentProcess() || h == (HANDLE)-1 || h == NULL) return o_NTP(h, s);
    DWORD p = GetProcessId(h);
    if (p == g_myPid || p == 0) return o_NTP(h, s);
    return 0;
}

static bool _IsOurWindow(HWND hw) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hw, &pid);
    return pid == g_myPid;
}

typedef BOOL (WINAPI* fn_PM)(HWND,UINT,WPARAM,LPARAM);
static fn_PM o_PMW = NULL;
BOOL WINAPI hk_PMW(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (TK_OK(0xA1u) && (msg == 0x10 || msg == 0x12 || msg == 0x02) && hw && !_IsOurWindow(hw))
        return TRUE;
    return o_PMW(hw, msg, wp, lp);
}

static fn_PM o_PMA = NULL;
BOOL WINAPI hk_PMA(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (TK_OK(0xA3u) && (msg == 0x10 || msg == 0x12 || msg == 0x02) && hw && !_IsOurWindow(hw))
        return TRUE;
    return o_PMA(hw, msg, wp, lp);
}

typedef LRESULT (WINAPI* fn_SM)(HWND,UINT,WPARAM,LPARAM);
static fn_SM o_SMW = NULL;
LRESULT WINAPI hk_SMW(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (TK_OK(0xA2u) && (msg == 0x10 || msg == 0x12 || msg == 0x02) && hw && !_IsOurWindow(hw))
        return 0;
    return o_SMW(hw, msg, wp, lp);
}

static fn_SM o_SMA = NULL;
LRESULT WINAPI hk_SMA(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (TK_OK(0xA4u) && (msg == 0x10 || msg == 0x12 || msg == 0x02) && hw && !_IsOurWindow(hw))
        return 0;
    return o_SMA(hw, msg, wp, lp);
}

typedef BOOL (WINAPI* fn_EW)(WNDENUMPROC, LPARAM);
static fn_EW o_EW = NULL;
BOOL WINAPI hk_EW(WNDENUMPROC cb, LPARAM lp) {
    struct Wrap { WNDENUMPROC orig; LPARAM origLp; DWORD pid; };
    Wrap w = { cb, lp, g_myPid };
    return o_EW([](HWND hw, LPARAM wlp) -> BOOL {
        Wrap* wr = (Wrap*)wlp;
        DWORD pid = 0;
        GetWindowThreadProcessId(hw, &pid);
        if (pid != wr->pid && IsWindowVisible(hw))
            return TRUE;
        return wr->orig(hw, wr->origLp);
    }, (LPARAM)&w);
}

typedef HANDLE (WINAPI* fn_OP)(DWORD, BOOL, DWORD);
static fn_OP o_OP = NULL;
HANDLE WINAPI hk_OP(DWORD access, BOOL inherit, DWORD pid) {
    if (TK_OK(0xC1u) && pid != g_myPid && pid != 0) {
        SetLastError(5);
        return NULL;
    }
    return o_OP(access, inherit, pid);
}

typedef BOOL (WINAPI* fn_P32N)(HANDLE, void*);
static fn_P32N o_P32NW = NULL;
BOOL WINAPI hk_P32NW(HANDLE snap, void* pe) {
    typedef struct { DWORD sz; DWORD cnt; DWORD th32; DWORD thcnt;
        DWORD thmod; DWORD flags; char exe[260]; } PE32;
    while (o_P32NW(snap, pe)) {
        PE32* p = (PE32*)pe;
        if (p->th32 == g_myPid || p->th32 == 0 || p->th32 == 4)
            return TRUE;
    }
    return FALSE;
}

static fn_P32N o_P32FW = NULL;
BOOL WINAPI hk_P32FW(HANDLE snap, void* pe) {
    if (!o_P32FW(snap, pe)) return FALSE;
    typedef struct { DWORD sz; DWORD cnt; DWORD th32; DWORD thcnt;
        DWORD thmod; DWORD flags; char exe[260]; } PE32;
    PE32* p = (PE32*)pe;
    if (p->th32 != g_myPid && p->th32 != 0 && p->th32 != 4)
        return hk_P32NW(snap, pe);
    return TRUE;
}

typedef BOOL (WINAPI* fn_SWP)(HWND,HWND,int,int,int,int,UINT);
static fn_SWP o_SWP = NULL;
BOOL WINAPI hk_SWP(HWND hw, HWND a, int x, int y, int cx, int cy, UINT f) {
    if (!TK_OK(0x33u)) return o_SWP(hw, a, x, y, cx, cy, f);
    if (a == HWND_TOPMOST) a = HWND_NOTOPMOST;
    return o_SWP(hw, a, x, y, cx, cy, f);
}

typedef HWND (WINAPI* fn_GFW)();
static fn_GFW o_GFW = NULL;
HWND WINAPI hk_GFW() {
    if (!TK_OK(0x44u)) return o_GFW();
    HWND r = o_GFW(); DWORD p = 0;
    GetWindowThreadProcessId(r, &p);
    if (p != g_myPid) { HWND l = FindLDB(); if (l) return l; }
    return r;
}

typedef BOOL (WINAPI* fn_EC)();
static fn_EC o_EC = NULL;
BOOL WINAPI hk_EC() { if (!TK_OK(0x55u)) return o_EC(); return TRUE; }

typedef LONG (WINAPI* fn_RSV)(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD);
static fn_RSV o_RSV = NULL;
LONG WINAPI hk_RSV(HKEY hk, LPCSTR n, DWORD r, DWORD t, const BYTE* d, DWORD cb) {
    if (!TK_OK(0x66u)) return o_RSV(hk, n, r, t, d, cb);
    if (n && (strstr(n, S("DisableTaskMgr")) || strstr(n, S("NoLogOff")) ||
              strstr(n, S("NoClose")) || strstr(n, S("DisableLockWorkstation")) ||
              strstr(n, S("DisableChangePassword"))))
        return ERROR_SUCCESS;
    return o_RSV(hk, n, r, t, d, cb);
}

typedef BOOL (WINAPI* fn_HSR)(HINTERNET,LPCSTR,DWORD,LPVOID,DWORD);
static fn_HSR o_HSR = NULL;
BOOL WINAPI hk_HSR(HINTERNET hR, LPCSTR hdr, DWORD hL, LPVOID body, DWORD bL) {
    if (!TK_OK(0x77u)) return o_HSR(hR, hdr, hL, body, bL);
    if (body && bL > 8) {
        char* b = (char*)body;
        bool dirty = false;
        for (DWORD i = 0; i + 6 < bL; i++) {
            if (*(DWORD*)(b+i) == 0x62646C72u) {
                for (DWORD j = i+4; j < bL-1 && j < i+24; j++) {
                    if (b[j] == '=' && (b[j+1] == '1' || b[j+1] == '2'))
                        { dirty = true; break; }
                    if (b[j] == '&' || b[j] == ' ' || b[j] == '\0') break;
                }
                if (dirty) break;
            }
        }
        if (dirty) {
            char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, bL+1);
            if (buf) {
                memcpy(buf, body, bL); buf[bL] = 0;
                for (DWORD i = 0; i + 6 < bL; i++) {
                    if (*(DWORD*)(buf+i) == 0x62646C72u) {
                        for (DWORD j = i+4; j < bL-1 && j < i+24; j++) {
                            if (buf[j] == '=' && (buf[j+1] == '1' || buf[j+1] == '2'))
                                { buf[j+1] = '0'; break; }
                            if (buf[j] == '&' || buf[j] == ' ' || buf[j] == '\0') break;
                        }
                    }
                }
                BOOL res = o_HSR(hR, hdr, hL, buf, bL);
                HeapFree(GetProcessHeap(), 0, buf);
                return res;
            }
        }
    }
    return o_HSR(hR, hdr, hL, body, bL);
}

typedef BOOL (WINAPI* fn_SPI)(UINT,UINT,PVOID,UINT);
static fn_SPI o_SPI = NULL;
BOOL WINAPI hk_SPI(UINT a, UINT p, PVOID v, UINT f) {
    if (!TK_OK(0x88u)) return o_SPI(a, p, v, f);
    if (a == SPI_SETSCREENSAVEACTIVE || a == SPI_SETFOREGROUNDLOCKTIMEOUT || a == SPI_SETSCREENSAVETIMEOUT)
        return TRUE;
    return o_SPI(a, p, v, f);
}

typedef HWND (WINAPI* fn_CWE)(DWORD,LPCWSTR,LPCWSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
static fn_CWE o_CWE = NULL;
HWND WINAPI hk_CWE(DWORD ex, LPCWSTR cls, LPCWSTR name, DWORD st,
    int x, int y, int w, int h, HWND par, HMENU menu, HINSTANCE inst, LPVOID param) {
    if (!TK_OK(0x99u)) return o_CWE(ex, cls, name, st, x, y, w, h, par, menu, inst, param);
    if (ex & WS_EX_TOPMOST) ex &= ~WS_EX_TOPMOST;
    return o_CWE(ex, cls, name, st, x, y, w, h, par, menu, inst, param);
}

typedef HDESK (WINAPI* fn_CDA)(LPCSTR,LPCSTR,DEVMODEA*,DWORD,ACCESS_MASK,SECURITY_ATTRIBUTES*);
static fn_CDA o_CDA = NULL;
HDESK WINAPI hk_CDA(LPCSTR n,LPCSTR d,DEVMODEA* dm,DWORD fl,ACCESS_MASK a,SECURITY_ATTRIBUTES* s) {
    if (!TK_OK(0xAAu)) return o_CDA(n,d,dm,fl,a,s);
    return g_defaultDesktop;
}

typedef HDESK (WINAPI* fn_CDW)(LPCWSTR,LPCWSTR,DEVMODEW*,DWORD,ACCESS_MASK,SECURITY_ATTRIBUTES*);
static fn_CDW o_CDW = NULL;
HDESK WINAPI hk_CDW(LPCWSTR n,LPCWSTR d,DEVMODEW* dm,DWORD fl,ACCESS_MASK a,SECURITY_ATTRIBUTES* s) {
    if (!TK_OK(0xBBu)) return o_CDW(n,d,dm,fl,a,s);
    return g_defaultDesktop;
}

typedef BOOL (WINAPI* fn_SD)(HDESK);
static fn_SD o_SD = NULL;
BOOL WINAPI hk_SD(HDESK h) { if (!TK_OK(0xCCu)) return o_SD(h); return TRUE; }

typedef BOOL (WINAPI* fn_STD)(HDESK);
static fn_STD o_STD = NULL;
BOOL WINAPI hk_STD(HDESK h) {
    if (!TK_OK(0xDDu)) return o_STD(h);
    if (h == g_defaultDesktop) return o_STD(h);
    return TRUE;
}

typedef BOOL (WINAPI* fn_CD)(HDESK);
static fn_CD o_CD = NULL;
BOOL WINAPI hk_CD(HDESK h) {
    if (h == g_defaultDesktop) return TRUE;
    return o_CD(h);
}

typedef HHOOK (WINAPI* fn_SHEW)(int,HOOKPROC,HINSTANCE,DWORD);
static fn_SHEW o_SHEW = NULL;
HHOOK WINAPI hk_SHEW(int id, HOOKPROC fn, HINSTANCE hm, DWORD tid) {
    if (!TK_OK(0xEEu)) return o_SHEW(id, fn, hm, tid);
    if (id == WH_KEYBOARD_LL || id == WH_KEYBOARD) return (HHOOK)0xDEAD0002;
    return o_SHEW(id, fn, hm, tid);
}

typedef HHOOK (WINAPI* fn_SHEA)(int,HOOKPROC,HINSTANCE,DWORD);
static fn_SHEA o_SHEA = NULL;
HHOOK WINAPI hk_SHEA(int id, HOOKPROC fn, HINSTANCE hm, DWORD tid) {
    if (!TK_OK(0xFFu)) return o_SHEA(id, fn, hm, tid);
    if (id == WH_KEYBOARD_LL || id == WH_KEYBOARD) return (HHOOK)0xDEAD0003;
    return o_SHEA(id, fn, hm, tid);
}

static DWORD WINAPI TopmostRemover(LPVOID)
{
    Sleep(3000);
    while (TK_OK(0x10u)) {
        Sleep(500);
        struct X { DWORD pid; fn_SWP swp; };
        X x = { g_myPid, o_SWP };
        EnumWindows([](HWND hw, LPARAM lp) -> BOOL {
            X* c = (X*)lp; DWORD pid;
            GetWindowThreadProcessId(hw, &pid);
            if (pid != c->pid) return TRUE;
            if (GetWindowLongA(hw, GWL_EXSTYLE) & WS_EX_TOPMOST)
                if (c->swp) c->swp(hw, HWND_NOTOPMOST, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
            return TRUE;
        }, (LPARAM)&x);
    }
    return 0;
}

static int _scmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *(unsigned char*)a - *(unsigned char*)b;
}

typedef FARPROC (WINAPI* fn_GPA)(HMODULE, LPCSTR);
static fn_GPA o_GPA = NULL;
FARPROC WINAPI hk_GPA(HMODULE hm, LPCSTR nm) {
    if (TK_OK(0xB1u) && (ULONG_PTR)nm > 0xFFFF) {
        char s0[]={'T','e','r','m','i','n','a','t','e','P','r','o','c','e','s','s',0};
        char s1[]={'E','m','p','t','y','C','l','i','p','b','o','a','r','d',0};
        char s2[]={'G','e','t','F','o','r','e','g','r','o','u','n','d','W','i','n','d','o','w',0};
        char s3[]={'S','e','t','W','i','n','d','o','w','P','o','s',0};
        char s4[]={'N','t','T','e','r','m','i','n','a','t','e','P','r','o','c','e','s','s',0};
        char s5[]={'P','o','s','t','M','e','s','s','a','g','e','W',0};
        char s6[]={'S','e','n','d','M','e','s','s','a','g','e','W',0};
        char s7[]={'P','o','s','t','M','e','s','s','a','g','e','A',0};
        char s8[]={'S','e','n','d','M','e','s','s','a','g','e','A',0};
        char s9[]={'E','n','u','m','W','i','n','d','o','w','s',0};
        if (_scmp(nm,s0)==0) return (FARPROC)hk_TP;
        if (_scmp(nm,s1)==0) return (FARPROC)hk_EC;
        if (_scmp(nm,s2)==0) return (FARPROC)hk_GFW;
        if (_scmp(nm,s3)==0) return (FARPROC)hk_SWP;
        if (_scmp(nm,s4)==0) return (FARPROC)hk_NTP;
        if (_scmp(nm,s5)==0) return (FARPROC)hk_PMW;
        if (_scmp(nm,s6)==0) return (FARPROC)hk_SMW;
        if (_scmp(nm,s7)==0) return (FARPROC)hk_PMA;
        if (_scmp(nm,s8)==0) return (FARPROC)hk_SMA;
        if (_scmp(nm,s9)==0) return (FARPROC)hk_EW;
        char sA[]={'O','p','e','n','P','r','o','c','e','s','s',0};
        char sB[]={'P','r','o','c','e','s','s','3','2','N','e','x','t','W',0};
        char sC[]={'P','r','o','c','e','s','s','3','2','F','i','r','s','t','W',0};
        if (_scmp(nm,sA)==0) return (FARPROC)hk_OP;
        if (_scmp(nm,sB)==0) return (FARPROC)hk_P32NW;
        if (_scmp(nm,sC)==0) return (FARPROC)hk_P32FW;
    }
    return o_GPA(hm, nm);
}

#define H(m,f,h,o) DoHook(m,f,(void*)h,(void**)&o)

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(hMod);
    g_selfMod = hMod;
    g_myPid = GetCurrentProcessId();
    g_defaultDesktop = GetThreadDesktop(GetCurrentThreadId());
    g_seed = GetCurrentProcessId() ^ GetTickCount();
    TK_INIT();
    LoadRealVersion();

    H(S("user32.dll"),   S("CreateDesktopA"),       hk_CDA, o_CDA);
    H(S("user32.dll"),   S("CreateDesktopW"),       hk_CDW, o_CDW);
    H(S("user32.dll"),   S("SwitchDesktop"),        hk_SD,  o_SD);
    H(S("user32.dll"),   S("SetThreadDesktop"),     hk_STD, o_STD);
    H(S("user32.dll"),   S("CloseDesktop"),         hk_CD,  o_CD);
    H(S("kernel32.dll"), S("TerminateProcess"),     hk_TP,  o_TP);
    H(S("ntdll.dll"),    S("NtTerminateProcess"),   hk_NTP, o_NTP);
    H(S("user32.dll"),   S("SetWindowsHookExW"),    hk_SHEW,o_SHEW);
    H(S("user32.dll"),   S("SetWindowsHookExA"),    hk_SHEA,o_SHEA);
    H(S("user32.dll"),   S("GetForegroundWindow"),  hk_GFW, o_GFW);
    H(S("user32.dll"),   S("SetWindowPos"),         hk_SWP, o_SWP);
    H(S("user32.dll"),   S("CreateWindowExW"),      hk_CWE, o_CWE);
    H(S("user32.dll"),   S("EmptyClipboard"),       hk_EC,  o_EC);
    H(S("advapi32.dll"), S("RegSetValueExA"),       hk_RSV, o_RSV);
    H(S("user32.dll"),   S("SystemParametersInfoW"),hk_SPI, o_SPI);
    H(S("wininet.dll"),  S("HttpSendRequestA"),     hk_HSR, o_HSR);
    H(S("user32.dll"),   S("PostMessageW"),         hk_PMW, o_PMW);
    H(S("user32.dll"),   S("PostMessageA"),         hk_PMA, o_PMA);
    H(S("user32.dll"),   S("SendMessageW"),         hk_SMW, o_SMW);
    H(S("user32.dll"),   S("SendMessageA"),         hk_SMA, o_SMA);
    H(S("user32.dll"),   S("EnumWindows"),          hk_EW,  o_EW);
    H(S("kernel32.dll"), S("OpenProcess"),           hk_OP,  o_OP);
    H(S("kernel32.dll"), S("Process32NextW"),        hk_P32NW, o_P32NW);
    H(S("kernel32.dll"), S("Process32FirstW"),       hk_P32FW, o_P32FW);
    H(S("kernel32.dll"), S("GetProcAddress"),        hk_GPA, o_GPA);

    FinalizePool();
    CreateThread(NULL, 0, TopmostRemover, NULL, 0, NULL);
    return TRUE;
}
