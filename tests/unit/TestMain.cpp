#include "Test.h"

#include <cstring>
#include <exception>

int main(int argc, char** argv)
{
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int passed = 0;
    int failed = 0;
    for (const auto& c : test::Registry()) {
        if (filter && !std::strstr(c.name, filter))
            continue;
        try {
            c.body();
            ++passed;
        } catch (const test::Failure& f) {
            ++failed;
            std::printf("FAIL %s\n     %s\n", c.name, f.message.c_str());
        } catch (const std::exception& e) {
            ++failed;
            std::printf("FAIL %s\n     unexpected exception: %s\n", c.name, e.what());
        }
    }
    std::printf("%d passed, %d failed, %d checks\n", passed, failed, test::CheckCount());
    return failed == 0 && passed > 0 ? 0 : 1;
}
