# TinyInst on Android

```
Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
## Cross-compiling TinyInst for Android

```
mkdir build-android
cd build-android
cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/android/ndk/build/cmake/android.toolchain.cmake -DANDROID_NDK=/path/to/android/ndk -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=<platform> ..
cmake --build . --config Release
```

## Limitations on Android

* Only ARM64 is supported at this time.
* Android has no support for Linux-style shared memory, which TinyInst needs to share a coverage buffer between TinyInst and the target process. As a temporary replacement, shared memory in TinyInst on Android is currently implemented by memory-mapping a file in `/data/local/tmp/`. While it may seem like this will be slow, note that TinyInst only writes to coverage buffer when new coverage is encountered. Thus, this workaround should not have a large impact after the initial warmup.
* `-generate_unwind` is not implemented on Android. For targets that throw C++ exceptions, `-patch_return_addresses` should be used instead.
