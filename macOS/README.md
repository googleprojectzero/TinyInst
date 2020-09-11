# TinyInst on macOS

```
Copyright 2020 Google LLC

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

## Limitations on macOS

* TinyInst may not always detect the exact time of target process exit. As a consequence the `OnProcessExit()` callback might have a maximum delay of 100ms. In the future, additional APIs (e.g. kqueue) could be used to detect process exit accurately.
* The coverage module that comes with TinyInst is unable to collect coverage at the time of process exit. The workaround for this at the moment is to define a target method and collect coverage at the time the target method exits. In the future, this will be resolved by allocating coverage buffer as shared memory.
* TinyInst on macOS has a `-gmalloc` flag, which enables Gurard Malloc when starting up a target process. However, at this time this flag is incompatible with the `-target_method` flag.
* TinyInst on macOS is affected by the same custom exceptions-handling issues as the Windows version. For the description of the issue and workarounds, see [this section in the readme](https://github.com/googleprojectzero/TinyInst#return-address-patching)