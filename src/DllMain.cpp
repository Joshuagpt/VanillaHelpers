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
            MH_Uninitialize();
        }
    }
    return TRUE;
}
