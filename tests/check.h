/* Проверки стендов tests/t_*.c: CHECK печатает место и условие и считает отказ. */
#ifndef BOX_TEST_CHECK_H
#define BOX_TEST_CHECK_H
#include <stdio.h>
static int t_fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: не выполнено: %s\n", __FILE__, __LINE__, #c); t_fails++; } } while (0)
#define T_DONE() (t_fails ? (fprintf(stderr, "отказов: %d\n", t_fails), 1) : 0)
#endif
