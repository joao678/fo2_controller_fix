# FlatOut 2 Controller Fix
This project aims to address some of the issues found while using a controller in FlatOut 2
## Features
- Menu controls on controller
- Up/Down analog stunt controls
- All control modes (Race/Stunt/Menu) change seamlessly based on the situation, no workarounds, no button combinations, everything changes automatically
- Optional PlayStation controller LED color based on the current vehicle's health (pass  "-extra-features" to the executable to enable)
- No changes to core game files other than dlls
- Runs in a different process
- uses [SDL](https://www.libsdl.org/) for compatibility with pretty much every controller
- uses [Frida](https://frida.re/) (server) and [frida-js](https://github.com/httptoolkit/frida-js) to intercept game functions
- uses [MemoryJS](https://github.com/Rob--/memoryjs/) to manipulate the game's memory
# Installing
1. Grab the latest release
2. Place all files from the zip in the game's folder
3. Connect the controller
4. Run FlatOut 2
5. Run fo2_controller_fix.exe