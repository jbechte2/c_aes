#include "../../include/aes_test.h"
#include "../../include/expand_key_test.h"

int main() {
    test_all_expand_key();
    test_all_aes();
    return 0;
}
