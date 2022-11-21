#include "sslhook.h"

bool IsPrintable(char *buf, size_t size) {
  for(size_t i=0; i<size; i++) {
    char c = buf[i];
    if((c == 0x09) || (c == 0x0A) || (c == 0x0D) ||
       ((c >= 0x20) && (c <= 0x7E)))
    {
      //pass
    } else {
      return false;
    }
  }
  return true;
}

void SSLWriteHook::OnFunctionEntered() {
  char *buf_addr = (char *)GetArg(1);
  size_t size = GetArg(2);
  
  if(size == 0) {
    printf("SSL_write: <empty>\n");
    return;
  }
  
  char *buf = (char *)malloc(size + 1);
  RemoteRead(buf_addr, buf, size);
  buf[size] = 0;

  if(IsPrintable(buf,size)) {
    printf("SSL_write: %s\n", buf);
  } else {
    printf("SSL_write: <binary, size=%zu>\n", size);
  }
  
  free(buf);
}

void SSLReadHook::OnFunctionReturned() {
  int retval = (int)GetReturnValue();
  
  if(retval <= 0) {
    printf("SSL_read: <empty>\n");
    return;
  }
  
  size_t size = retval;
  char *buf_addr = (char *)GetArg(1);

  char *buf = (char *)malloc(size + 1);
  RemoteRead(buf_addr, buf, size);
  buf[size] = 0;

  if(IsPrintable(buf,size)) {
    printf("SSL_read: %s\n", buf);
  } else {
    printf("SSL_read: <binary, size=%zu>\n", size);
  }
  
  free(buf);
}

SSLInst::SSLInst() {
  RegisterHook(new SSLReadHook());
  RegisterHook(new SSLWriteHook());
}


