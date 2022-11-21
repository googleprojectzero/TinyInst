/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef SSLINST_H
#define SSLINST_H

#include "hook.h"

class SSLWriteHook : public HookBegin {
public:
  SSLWriteHook() : HookBegin("*", "SSL_write", 3, CALLCONV_DEFAULT) {}
protected:
  void OnFunctionEntered() override;
};

class SSLReadHook : public HookBeginEnd {
public:
  SSLReadHook() : HookBeginEnd("*", "SSL_read", 3, CALLCONV_DEFAULT) {}
protected:
  void OnFunctionReturned() override;
};

class SSLInst : public TinyInst {
public:
  SSLInst();
};
  
#endif /* SSLINST_H */
