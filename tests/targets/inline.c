#include <stdio.h>
__attribute__((always_inline)) void a() { printf("a\n"); }
__attribute__((always_inline)) void b() { a(); }
__attribute__((always_inline)) void c() { b(); }

int main() {
  c();
  return 0;
}