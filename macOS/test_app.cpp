#include <iostream>

int main(int argc, char **argv) {
  if (argc != 2) {
    return -1;
  }
  std::string test(argv[1]);

  if(test == "hello_world" || test == "loop") {
    std::cout << "hello_world\n";
  }

  else if(test == "hang") {
    while(1);
  }

  else if(test == "stack_corruption") {
    char foo[10];
    strcpy(foo, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  }

  else if(test == "invalid_addr_access") {
    *((int*)((unsigned long long)argc))=0;
  }

  else if(test == "exit") {
    exit(0);
  }
  return 0;
}