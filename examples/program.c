// A stand-in for a compiler: it "crashes" on programs containing a loop guard
// of the form `if (x ... != 0`. Starting from corpus/seed.c, which has
// `while (x == 0)`, that takes two source-level edits (`while` -> `if` and
// `==` -> `!=`), which the mutation-testing operators make directly and
// byte-level havoc rarely does.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  FILE *file = stdin;
  if (argc > 1) { file = fopen(argv[1], "rb"); }
  if (!file) { return 1; }

  static char buf[65536];
  size_t      len = fread(buf, 1, sizeof(buf) - 1, file);
  buf[len] = 0;

  char *guard = strstr(buf, "if (x");
  if (guard && strstr(guard, "!= 0")) { abort(); }

  return 0;
}
