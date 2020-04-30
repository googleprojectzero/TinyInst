#include <list>

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

#define SAY(...)    printf(__VA_ARGS__)

#define WARN(...) do { \
    SAY("[!] WARNING: " __VA_ARGS__); \
    SAY("\n"); \
  } while (0)

#define FATAL(...) do { \
    SAY("[-] PROGRAM ABORT : " __VA_ARGS__); \
    SAY("         Location : %s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

#define USAGE_CHECK(condition, message) if(!(condition)) FATAL("%s\n", message);

// gets time in milliseconds
uint64_t GetCurTime(void);

char *GetOption(char *name, int argc, char** argv);
void GetOptionAll(char *name, int argc, char** argv, std::list<char *> *results);

char *ArgvToCmd(int argc, char** argv);