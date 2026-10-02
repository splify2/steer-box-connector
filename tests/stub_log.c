/* Журнал коннектора для стендов: box_log живёт в main.c рядом с main(), поэтому здесь свой. */
#include "box.h"
#include <stdarg.h>
#include <stdio.h>

void box_log_level(enum box_level min) { (void)min; }

void box_log(enum box_level lvl, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "log%d: ", (int)lvl);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}
