/*
MIT License

Copyright (c) 2025 Qwanwin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef AETHER_HOOK_H
#define AETHER_HOOK_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h> 

#ifndef AETHER_HOOK_LOG_TAG
#define AETHER_HOOK_LOG_TAG "AetherHook"
#endif

/**
 * @brief Main namespace for the AetherHook library.
 * 
 * AetherHook provides functionality for hooking functions in shared libraries (PLT hooks)
 * and inline functions within code (inline hooks) on Android platforms, especially for AArch64 architecture.
 * This is useful for debugging, instrumentation, or dynamically modifying application behavior.
 */
namespace AetherHook {

    // API
    /**
     * @brief Initializes the AetherHook library.
     * 
     * This function must be called before using other APIs.
     * It ensures that internal components are ready for use.
     * Automatic initialization was removed to give users more control.
     */
    void initialize();

    /**
     * @brief Enables or disables debug mode.
     * 
     * Debug mode activates detailed log messages that assist in debugging processes.
     * 
     * @param enable If true, debug mode is enabled. If false, it is disabled.
     */
    void enable_debug(bool enable);

    /**
     * @brief Retrieves the version string of the AetherHook library.
     * 
     * @return The version string of the library.
     */
    const char* version();

    /**
     * @brief Prints an informational log message to Android logcat.
     * 
     * @param fmt Format string for the log message, followed by optional arguments.
     */
    void logi(const char* fmt, ...);

    /**
     * @brief Prints a debug-level log message to Android logcat (only if debug mode is enabled).
     * 
     * @param fmt Format string for the log message, followed by optional arguments.
     */
    void logd(const char* fmt, ...);

    /**
     * @brief Prints an error-level log message to Android logcat.
     * 
     * @param fmt Format string for the log message, followed by optional arguments.
     */
    void loge(const char* fmt, ...);

    /**
     * @brief Applies all registered hooks.
     * 
     * This function must be called after registering hooks (both PLT and Inline)
     * and after the target module (if PLT hook) is likely loaded.
     * It searches for the corresponding modules and applies the patches.
     * 
     * @param sync Optional synchronization parameter (currently not effectively used).
     * @return 0 on success, -1 on error.
     */
    int refresh(int sync = 0);

    /**
     * @brief Namespace for functions related to PLT (Procedure Linkage Table) hooking.
     * 
     * PLT hooking replaces function calls to symbols found in dynamically linked shared libraries
     * by modifying entries in the GOT (Global Offset Table).
     */
    namespace PLT {
        /**
         * @brief Registers a PLT hook.
         * 
         * This hook replaces the target function in matching shared libraries using
         * a POSIX regular expression for the library path and the given symbol name.
         * 
         * @param pathname_regex POSIX regular expression to match the shared library path (e.g., ".*libc.*\\.so$").
         * @param symbol The name of the symbol (function) to hook.
         * @param new_func Pointer to the replacement function.
         * @param old_func_out Optional pointer to a variable that will be filled with the address of the original function.
         *                     The original function should be called from the replacement function to maintain functionality.
         * @return 0 on success, -1 on error (e.g., invalid arguments).
         */
        int register_hook(const char *pathname_regex, const char *symbol, void *new_func, void **old_func_out = nullptr);
        void apply_all_hooks(); 
        // int remove_hook(const char *pathname_regex, const char *symbol); // Removed for simplicity
    }

    /**
     * @brief Namespace for functions related to inline hooking.
     * 
     * Inline hooking directly modifies the first few instructions of a target function in memory,
     * redirecting execution to a replacement function. It is more complex and risky than PLT hooking.
     */
    namespace Inline {
        /**
         * @brief Registers an inline hook.
         * 
         * This hook replaces the initial instructions of the function located at `target_addr`
         * with a jump to `new_func`.
         * 
         * @param target_addr Memory address of the original function to be hooked.
         * @param new_func Pointer to the replacement function.
         * @param old_func_out Optional pointer to a variable that will be filled with the address of the trampoline.
         *                     The trampoline contains the relocated original instructions and a jump back
         *                     to the remaining part of the original function.
         *                     The original function (trampoline) should be called from the replacement function
         *                     to preserve functionality.
         * @return 0 on success, -1 on error (e.g., invalid arguments, unsupported architecture).
         */
        int register_hook(void *target_addr, void *new_func, void **old_func_out = nullptr);
        void apply_all_hooks();
        // int remove_hook(void *target_addr); // Removed for simplicity
    }

} // namespace AetherHook

#endif // AETHER_HOOK_H
