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
