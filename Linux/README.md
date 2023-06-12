# TinyInst on Linux

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

## Limitations on Linux

* Only x86 and x86-64 binaries are supported at this time. Support for ARM64 binaries is planned.
* TinyInst supports 32-bit x86 binaries running on a 64-bit OS (support for a 32-bit Linux OS is not planned at this time). However, such 32-bit binaries commonly read return addresses from the stack. This breaks TinyInst unless `-patch_return_addresses` is used. A warning to enable the flag will be printed if such a case is encountered.
