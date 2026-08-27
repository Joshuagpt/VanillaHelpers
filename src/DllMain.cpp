// This file is part of VanillaHelpers.
//
// VanillaHelpers is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lessed General Public License along with
// VanillaHelpers. If not, see <https://www.gnu.org/licenses/>.

#include "Allocator.h"
#include "Blips.h"
#include "Common.h"
#include "FileIO.h"
#include "Game.h"
#include "MinHook.h"
#include "Morph.h"
#include "Offsets.h"
#include "Texture.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <tlhelp32.h>
#include <windows.h>

static Game::InitializeGlobal_t InitializeGlobal_o = nullptr;
static Game::FrameScript_Initialize_t FrameScript_Initialize_o = nullptr;
static Game::LoadScriptFunctions_t LoadScriptFunctions_o = nullptr;
static Game::CGGameUI_Shutdown_t CGGameUI_Shutdown_o = nullptr;

static void __fastcall InvalidFunctionPtrCheck_h() {}

static bool __fastcall InitializeGlobal_h() {
    bool ok = InitializeGlobal_o();
    Texture::InstallCharacterSkin();
    return ok;
}

static bool __fastcall FrameScript_Initialize_h() {
    FrameScript_Initialize_o();
    const std::string luaScript =
        "VANILLAHELPERS_VERSION=" + std::to_string(VANILLAHELPERS_VERSION_VALUE) +
        "\nVANILLA_HELPERS_VERSION=" + std::to_string(VANILLAHELPERS_VERSION_VALUE);
    Game::FrameScript_Execute(luaScript.c_str(), "VanillaHelpers.lua");
    return true;
}

static void __fastcall LoadScriptFunctions_h() {
    LoadScriptFunctions_o();
    FileIO::RegisterLuaFunctions();
    Blips::RegisterLuaFunctions();
    Morph::RegisterLuaFunctions();
}

static void __fastcall CGGameUI_Shutdown_h() {
    Morph::Reset();
    CGGameUI_Shutdown_o();
    Blips::Reset();
}

// ── Diagnostics: capture the game's own fatal-error dialogs ──
// The "ERROR #124 ... SMem3: Pointer does not refer to a valid allocated
// block of memory" dialog (and any other "This application has encountered
// a critical error" dialog) is very likely raised by the engine's own
// internal validation code calling straight into a "display error and
// terminate" routine, not by a genuine CPU-level exception — which is
// exactly why Windows Error Reporting's LocalDumps (which only fires on
// unhandled SEH exceptions reaching the top of the stack) produces nothing
// for it: from the OS's point of view nothing ever actually faulted.
//
// There's no verified offset for that internal "display error" routine in
// this client to hook directly, and guessing one risks corrupting
// unrelated code. But whatever internal path builds that dialog has to
// eventually call the standard, publicly documented Win32 MessageBoxA to
// actually draw it, so hooking that instead gives the same visibility
// without touching any internal engine address. This hook is fully
// transparent: it only observes and logs, then calls through to the real
// MessageBoxA unchanged, so the dialog behaves exactly as before.
static decltype(&MessageBoxA) MessageBoxA_o = nullptr;

// Shared by both crash-adjacent hooks below: writes a timestamped block with a raw + exeBase-
// relative stack trace to the same VanillaHelpersData/CrashLog.txt used elsewhere in this
// project, then flushes immediately (not buffered) since it isn't known whether the game's
// crash handling calls ExitProcess or TerminateProcess afterward.
static void WriteStackTraceBlock(const char *header, const std::string &extraLines) {
    constexpr int MAX_FRAMES = 32;
    void *frames[MAX_FRAMES] = {};
    USHORT frameCount = CaptureStackBackTrace(0, MAX_FRAMES, frames, nullptr);

    std::error_code ec;
    std::filesystem::create_directories("VanillaHelpersData", ec);
    std::ofstream out("VanillaHelpersData/CrashLog.txt", std::ios::app);
    if (!out)
        return;

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    struct tm tmBuf {};
    localtime_s(&tmBuf, &t);
    char timeBuf[16];
    strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tmBuf);

    HMODULE exeBase = GetModuleHandleA(nullptr);

    out << "==== " << header << " [" << timeBuf << "." << std::setfill('0') << std::setw(3)
        << ms.count() << "] thread=" << GetCurrentThreadId() << " exeBase=" << exeBase
        << " ====\n";
    out << extraLines;
    out << "stack (" << frameCount << " frames, raw addr / offset from exeBase):\n";
    for (USHORT i = 0; i < frameCount; ++i) {
        auto addr = reinterpret_cast<uintptr_t>(frames[i]);
        auto base = reinterpret_cast<uintptr_t>(exeBase);
        out << "  #" << i << " " << frames[i];
        if (addr >= base)
            out << " (exe+0x" << std::hex << (addr - base) << std::dec << ")";
        out << "\n";
    }
    out << "\n";
    out.flush();
}

static void CaptureCrashDialog(LPCSTR text, LPCSTR caption) {
    std::ostringstream extra;
    extra << "caption: " << (caption ? caption : "(null)") << "\n";
    extra << "text: " << (text ? text : "(null)") << "\n";
    WriteStackTraceBlock("MessageBox", extra.str());
}

static int WINAPI MessageBoxA_h(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    CaptureCrashDialog(lpText, lpCaption);
    return MessageBoxA_o(hWnd, lpText, lpCaption, uType);
}

// ── Diagnostics: SMem3's own "raise error #N" function ──
// Confirmed via disassembly of the uploaded WoW.exe (not a guessed offset): __fastcall(int
// errorCode /*ecx*/, void *object /*edx*/, DWORD extra /*[ebp+8]*/). This is the closest
// verified point to SMem3's actual "is this pointer valid" check — it's called directly by
// whichever validation code decided to raise the error, one hop earlier than MessageBoxA_h
// above, so a stack trace captured here has a much better chance of reaching back into the
// caller responsible (e.g. WMO/portal-related code) before the naive frame-pointer-less x86
// walk loses track. It also lets us log the raw errorCode and object pointer directly, which
// the MessageBoxA-based capture couldn't recover on its own.
typedef void(__fastcall *SMem3RaiseError_t)(int errorCode, void *object, DWORD extra);
static SMem3RaiseError_t SMem3RaiseError_o = nullptr;

static void __fastcall SMem3RaiseError_h(int errorCode, void *object, DWORD extra) {
    std::ostringstream extraLines;
    extraLines << "errorCode: " << errorCode << " (0x" << std::hex << errorCode << std::dec
               << ")\n";
    extraLines << "object: " << object << "\n";
    extraLines << "extra(stack arg): 0x" << std::hex << extra << std::dec << "\n";
    WriteStackTraceBlock("SMem3RaiseError", extraLines.str());
    SMem3RaiseError_o(errorCode, object, extra);
}

// ── Diagnostics: hardware watchpoint on the SMem3 deferred-error flag ──
// Disassembly traced the SGroupPtr/SMem3 #124 report back to a tiny "flush pending error"
// function that just reads a fixed global (0xCE6738) and, if nonzero, raises whatever code is
// stored there. The only place that WRITES 0xCE6738 as a literal address is a reset-to-zero
// at some init point; the real write of the fault code must happen through register-indirect
// addressing (e.g. a struct-base register + offset), which a plain search for the address as
// an immediate operand can't find. Rather than guess further, this uses actual x86 hardware
// debug registers (Dr0/Dr7) to set a CPU-level write watchpoint on that address: the CPU
// itself raises EXCEPTION_SINGLE_STEP the moment ANY instruction writes there, regardless of
// how the address was computed, and our vectored exception handler below logs the instruction
// pointer, registers, and a stack trace at that exact moment, then lets execution continue
// completely unchanged. Debug registers are per-thread, so a background thread periodically
// re-applies the watchpoint to every thread in the process to also catch ones created after
// the first pass.
static constexpr uintptr_t WATCH_ADDR = 0xCE6738;
static PVOID g_watchpointVeh = nullptr;
static volatile LONG g_watchpointHits = 0;
static HANDLE g_watchpointStopEvent = nullptr;
static HANDLE g_watchpointThread = nullptr;

static void ApplyWatchpointToThread(HANDLE hThread) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx))
        return;

    ctx.Dr0 = WATCH_ADDR;
    // Dr7: L0 (bit 0) enables breakpoint 0 for this thread; R/W0 (bits 16-17) = 01 selects
    // write-only; LEN0 (bits 18-19) = 11 selects a 4-byte range. Leave every other
    // breakpoint slot and reserved bit untouched.
    ctx.Dr7 = (ctx.Dr7 & ~(0xFu << 16)) | (0x1u << 16) | (0x3u << 18) | 0x1u;

    SetThreadContext(hThread, &ctx);
}

static void ApplyWatchpointToAllThreads() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid)
                continue;
            HANDLE hThread =
                OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                ApplyWatchpointToThread(hThread);
                CloseHandle(hThread);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static DWORD WINAPI WatchpointRefreshThread(LPVOID) {
    // Waits on the stop event instead of Sleep()ing so an explicit unload (see
    // DLL_PROCESS_DETACH below) can wake this thread and let it exit cleanly before the DLL is
    // unmapped — unlike a plain Sleep loop, this thread's code would otherwise still be
    // executing after FreeLibrary() removes it from memory. On real process termination this
    // event is never signaled and the thread is simply torn down with the rest of the
    // process, which is fine since it holds no locks or cross-process resources.
    while (WaitForSingleObject(g_watchpointStopEvent, 2000) == WAIT_TIMEOUT) {
        ApplyWatchpointToAllThreads();
    }
    return 0;
}

static LONG WINAPI WatchpointVEH(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    // Confirm this was our breakpoint 0 (Dr6 bit 0 = B0), not an unrelated single-step (e.g.
    // from an attached debugger), before treating it as a hit.
    if (!(info->ContextRecord->Dr6 & 0x1))
        return EXCEPTION_CONTINUE_SEARCH;

    LONG hitNum = InterlockedIncrement(&g_watchpointHits);

    constexpr int MAX_FRAMES = 32;
    void *frames[MAX_FRAMES] = {};
    USHORT frameCount = CaptureStackBackTrace(0, MAX_FRAMES, frames, nullptr);

    std::error_code ec;
    std::filesystem::create_directories("VanillaHelpersData", ec);
    std::ofstream out("VanillaHelpersData/CrashLog.txt", std::ios::app);
    if (out) {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        struct tm tmBuf {};
        localtime_s(&tmBuf, &t);
        char timeBuf[16];
        strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tmBuf);

        HMODULE exeBase = GetModuleHandleA(nullptr);
        auto exeBaseAddr = reinterpret_cast<uintptr_t>(exeBase);
        auto eip = static_cast<uintptr_t>(info->ContextRecord->Eip);

        out << "==== Watchpoint 0xCE6738 write [" << timeBuf << "." << std::setfill('0')
            << std::setw(3) << ms.count() << "] thread=" << GetCurrentThreadId() << " hit#"
            << hitNum << " exeBase=" << exeBase << " ====\n";
        out << "EIP: 0x" << std::hex << eip;
        if (eip >= exeBaseAddr)
            out << " (exe+0x" << (eip - exeBaseAddr) << ")";
        out << std::dec << "\n";
        out << "EAX=0x" << std::hex << info->ContextRecord->Eax
            << " EBX=0x" << info->ContextRecord->Ebx << " ECX=0x" << info->ContextRecord->Ecx
            << " EDX=0x" << info->ContextRecord->Edx << " ESI=0x" << info->ContextRecord->Esi
            << " EDI=0x" << info->ContextRecord->Edi << std::dec << "\n";
        out << "stack (" << frameCount << " frames, raw addr / offset from exeBase):\n";
        for (USHORT i = 0; i < frameCount; ++i) {
            auto addr = reinterpret_cast<uintptr_t>(frames[i]);
            out << "  #" << i << " " << frames[i];
            if (addr >= exeBaseAddr)
                out << " (exe+0x" << std::hex << (addr - exeBaseAddr) << std::dec << ")";
            out << "\n";
        }
        out << "\n";
        out.flush();
    }

    // Reset Dr6 so the trap-status bits are clean for the next hit, and let the faulting
    // instruction's effects stand — this handler only observes, it never alters behavior.
    info->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        Allocator::Initialize();
        Texture::Initialize();

        if (MH_Initialize() != MH_OK)
            return FALSE;

        auto *target = reinterpret_cast<LPVOID>(Offsets::FUN_INVALID_FUNCTION_PTR_CHECK);
        if (MH_CreateHook(target, static_cast<LPVOID>(InvalidFunctionPtrCheck_h), nullptr) != MH_OK)
            return FALSE;
        if (MH_EnableHook(target) != MH_OK)
            return FALSE;

        HOOK_FUNCTION(Offsets::FUN_INITIALIZE_GLOBAL, InitializeGlobal_h, InitializeGlobal_o);
        HOOK_FUNCTION(Offsets::FUN_FRAME_SCRIPT_INITIALIZE, FrameScript_Initialize_h,
                      FrameScript_Initialize_o);
        HOOK_FUNCTION(Offsets::FUN_LOAD_SCRIPT_FUNCTIONS, LoadScriptFunctions_h,
                      LoadScriptFunctions_o);
        HOOK_FUNCTION(Offsets::FUN_CGGAMEUI_SHUTDOWN, CGGameUI_Shutdown_h, CGGameUI_Shutdown_o);
        HOOK_FUNCTION(Offsets::FUN_SMEM3_RAISE_ERROR, SMem3RaiseError_h, SMem3RaiseError_o);

        // MessageBoxA is a real, stable, documented Win32 export (not a guessed internal
        // engine offset), so it's hooked the same way as everything above via its resolved
        // address rather than a raw Offsets:: constant.
        {
            auto *target = reinterpret_cast<LPVOID>(&MessageBoxA);
            if (MH_CreateHook(target, static_cast<LPVOID>(MessageBoxA_h),
                              reinterpret_cast<LPVOID *>(&MessageBoxA_o)) != MH_OK)
                return FALSE;
            if (MH_EnableHook(target) != MH_OK)
                return FALSE;
        }

        if (!Allocator::InstallHooks())
            return FALSE;
        if (!Texture::InstallHooks())
            return FALSE;

        // Install the hardware watchpoint's exception handler first, then apply it to every
        // existing thread, then keep a background thread re-applying it every couple of
        // seconds to also catch threads created later (debug registers are per-thread and
        // don't carry over automatically).
        g_watchpointVeh = AddVectoredExceptionHandler(1, WatchpointVEH);
        ApplyWatchpointToAllThreads();
        g_watchpointStopEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        g_watchpointThread =
            CreateThread(nullptr, 0, WatchpointRefreshThread, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        // lpReserved != nullptr means the process is terminating (e.g. the user quit the
        // game and the OS called ExitProcess), as opposed to an explicit FreeLibrary() call.
        // In that case most threads are already gone/frozen and the process address space is
        // about to be torn down wholesale, so touching code pages here (MH_Uninitialize
        // restores our inline hooks by writing back original bytes via VirtualProtect) is both
        // unnecessary and unsafe: it can race with in-flight engine cleanup code (e.g. the
        // group manager singleton freeing SGroupPtr) that still expects our hooks / patched
        // allocator behavior to be in effect, and the earlier permanent Common::PatchBytes
        // patches in Allocator::Initialize() are never reverted anyway, so partially unhooking
        // here just creates an inconsistent half-patched allocator state.
        // Skip all cleanup on process termination; only unhook on a genuine explicit unload.
        if (lpReserved == nullptr) {
            if (g_watchpointStopEvent) {
                SetEvent(g_watchpointStopEvent);
                if (g_watchpointThread)
                    WaitForSingleObject(g_watchpointThread, 3000);
            }
            if (g_watchpointThread) {
                CloseHandle(g_watchpointThread);
                g_watchpointThread = nullptr;
            }
            if (g_watchpointStopEvent) {
                CloseHandle(g_watchpointStopEvent);
                g_watchpointStopEvent = nullptr;
            }
            if (g_watchpointVeh) {
                RemoveVectoredExceptionHandler(g_watchpointVeh);
                g_watchpointVeh = nullptr;
            }
            MH_Uninitialize();
        }
    }
    return TRUE;
}
