#include <assert.h>
#include "../src/virtual.c"

int main(void)
{
    unsigned char p[64] = {};
    unsigned int net = 0xac170000U, mask = 0xffff0000U;
    volatile sig_atomic_t stop = 1;
    p[12] = 8; p[14] = 0x45;
    p[26] = 172; p[27] = 23; p[28] = 1; p[29] = 1;
    p[30] = 172; p[31] = 23; p[32] = 1; p[33] = 2;
    assert(overlay_frame(p, 34, net, mask, false));
    assert(overlay_frame(p, 34, net, mask, true));
    assert(!overlay_frame(p, 33, net, mask, true));
    p[27] = 21;
    assert(!overlay_frame(p, 34, net, mask, false));
    p[31] = 22;
    assert(!overlay_frame(p, 34, net, mask, true));
    memset(p + 30, 255, 4);
    assert(!overlay_frame(p, 34, net, mask, true));
    p[27] = 23;
    assert(overlay_frame(p, 34, net, mask, true));
    p[13] = 6; p[14] = 0; p[15] = 1; p[16] = 8;
    p[18] = 6; p[19] = 4; p[38] = 172; p[39] = 23;
    assert(overlay_frame(p, 42, net, mask, true));
    assert(!overlay_frame(p, 41, net, mask, true));
    p[39] = 21;
    assert(!overlay_frame(p, 42, net, mask, true));
    p[12] = 0x86; p[13] = 0xdd;
    assert(!overlay_frame(p, 64, net, mask, false));
    assert(dnet2_virtual_run("bad%name", "172.23.1.1/16", "a", "b", &stop) == -EINVAL);
    assert(dnet2_virtual_run("dnet2", "172.21.1.1/16", "a", "b", &stop) == -EINVAL);
    assert(dnet2_virtual_run("dnet2", "172.23.0.0/16", "a", "b", &stop) == -EINVAL);
    puts("virtual adapter packet and configuration tests passed");
}
