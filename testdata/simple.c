#include <sys/sdt.h>

int main() {
    for (;;) {
        DTRACE_PROBE1(X, Y, 1);
    }
    return 0;
}
