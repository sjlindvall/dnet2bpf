#ifndef DNET2_VIRTUAL_H
#define DNET2_VIRTUAL_H
#include <signal.h>
int dnet2_virtual_run(const char *name, const char *cidr,
                      const char *a, const char *b,
                      volatile sig_atomic_t *exiting);
#endif
