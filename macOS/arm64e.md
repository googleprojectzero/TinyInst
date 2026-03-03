# Running against arm64e binaries

Note: There is a high probability you don't need this. By default, all binaries you compile yourself on Apple silicom macs will be arm64 (and *not* arm64e) binaries. E.g. a fuzzing harness you wrote yourself will be an arm64 binary even if it loads libraries made and signed by Apple. Only binaries that ship with the system and are signed by Apple will be arm64e binaries. You can always check which architecture a binary is compiled for by running the `file` command against it.

In order to successfully run TinyInst or Jackalope against arm64e binaries, you need to do the following:

1. Disable System Integrity Protection (SIP) by following instructions [here](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection).

2. Enable arm64e ABI and disable Apple Mobile File Integrity (AMFI) by running the following command
```
sudo nvram boot-args="-arm64e_preview_abi amfi_get_out_of_my_way=1"
```
and restarting the system.

3. Build arm64e version of TinyInst / Jackalope by running the following commands from the source directory. This is the same build process as usual but with `-DCMAKE_OSX_ARCHITECTURES=arm64e` argument added.

```
mkdir buildarm64e
cd buildarm64e
cmake -G Xcode -DCMAKE_OSX_ARCHITECTURES=arm64e ..
cmake --build . --config Release
```

4. You might also need to add additional entitlements to your TinyInst / Jackalope binaries by running
```
codesign -f -s - --entitlements path/to/TinyInst/arm64e.entitlements path/to/litecov/or/fuzzer
```

You should be able to run successfully against an arm64e binary now, e.g.
```
/path/to/litecov -instrument_module ls -- /bin/ls .
```
