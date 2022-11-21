## Hook API

In addition to the general-purpose low-level API that allows inserting code on every instruction, basic block or edge, TinyInst also implements a hooking API that is better suited for inspecting and modifying behavior of individual functions.

Users can write hooks by creating a class (for each function they wish to hook) that inherits from one of the Hook classes explained below. Inside the class constructor, the user describes the function they want to hook by specifying module name (`*` applies the hook to all instrumented modules), function name or offset, number of function arguments and the calling convention.

Currently implemented Hook classes are

 - `HookReplace` - Useful for completely replacing the implementation of a function (the original function code never runs). The user gets a breakpoint when the function is supposed to run which they can then handle by implementing `OnFunctionEntered` method. The user also gets the ability to insert alternate function assembly by implementing `WriteCodeBefore` method.

 - `HookBegin` - Hooks just the start of the function. The original function code runs, but before it does, the user gets a breakpointwhich (`OnFunctionEntered`). The user also gets the ability to insert assembly code that runs before the original function implementation by implementing `WriteCodeBefore` method.

 - `HookBeginEnd` - Hooks both the start and the end of the function. The user gets a breakpoint both when the function enters (`OnFunctionEntered`) and immediately after the function returns (`OnFunctionReturned`). The user can also insert additional assembly code that runs before the function code (`WriteCodeBefore`) and after the function returns (`WriteCodeAfter`).

In all cases the order of events when calling the hooked function is
 - Breakpoint handler `OnFunctionEntered` gets called.
 - Code inserted during `WriteCodeBefore` runs .
 - (Except in `HookReplace`) Original function code runs.
 - (In `HookBeginEnd`) Code inserted during `WriteCodeAfter` runs.
 - (In `HookBeginEnd`) Breakpoint handler `OnFunctionReturned` gets called.

It is expected that most hooking operations can be performed just using the breakpoint handlers without the need to insert assembly code. Note however that breakpoint handlers run in a process (TinyInst process) different than the target process. This means that any memory read/write operations on the target process must be performed using `RemoteRead`/`RemoteWrite` instead of reading/writing memory directly. There are other useful function the breakpoint handlers can call such as for getting ans setting function arguments (`GetArg/SetArg`), getting and setting registers (`GetRegister`/`SetRegister`), getting and setting function return value (`GetReturnValue`/`SetReturnValue`, mostly useful inside the `OnFunctionReturned` or inside `OnFunctionEntered` for `HookReplace`) and allocating memory in the target process (`RemoteAllocate`).

If a hook needs to add additional assembly code, this can be done by implementing `WriteCodeBefore`/`WriteCodeAfter` methods of the hook class. Assembly code can be inserted by calling the `WriteCode` function with the buffer containing the assembly to be inserted. Note that both `WriteCodeBefore`/`WriteCodeAfter` get called during instrumentation time (before the function gets run) and, due to how `HookBeginEnd` is implemented, `WriteCodeAfter` can be called multiple times for a single hooked function.

Once the hook classes have been implemented for each function the user wants to hook, the user can register them by calling `RegisterHook` method inside their clien's constructor.

### Example

A small example on how to use the Hook API is provided in [sslhook.h](https://github.com/googleprojectzero/TinyInst/blob/master/sslhook.h) and [sslhook.cpp](https://github.com/googleprojectzero/TinyInst/blob/master/sslhook.cpp).

These files implement hooks for SSL_read and SSL_write functions, to be applied to all instrumented modules. These hooks inspects content sent/received during SSL_write/SSL_read and print it out to console (if it's printable).

The main executable for the `SSLInst` client is implemented in [sslhook-main.cpp](https://github.com/googleprojectzero/TinyInst/blob/master/sslhook-main.cpp).


