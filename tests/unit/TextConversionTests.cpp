#include "Test.h"
#include "TextConversion.h"

#include <string>
#include <vector>

using text_conversion::CrLfToLf;
using text_conversion::LfToCrLf;

namespace {

std::string ToCrLf(const std::string& in)
{
    LfToCrLf conv;
    std::vector<char> out;
    conv.Convert(in.data(), in.size(), out);
    return {out.begin(), out.end()};
}

std::string ToLf(const std::string& in)
{
    CrLfToLf conv;
    std::vector<char> out;
    conv.Convert(in.data(), in.size(), out);
    conv.Finish(out);
    return {out.begin(), out.end()};
}

// Splits `in` at random points; empty chunks are included on purpose.
std::vector<std::string> RandomChunks(const std::string& in, test::Rng& rng)
{
    std::vector<std::string> chunks;
    size_t pos = 0;
    while (pos < in.size()) {
        const size_t n = rng.Below(5) == 0 ? 0 : 1 + rng.Below(in.size() - pos);
        chunks.push_back(in.substr(pos, n));
        pos += n;
    }
    chunks.emplace_back();
    return chunks;
}

// Random text over the bytes that matter to the state machines.
std::string RandomText(test::Rng& rng, size_t maxLen)
{
    static constexpr char alphabet[] = {'a', 'b', '\r', '\n', '\r', '\n', '\0', '\x7f'};
    std::string s(rng.Below(maxLen + 1), '\0');
    for (auto& c : s)
        c = alphabet[rng.Below(sizeof(alphabet))];
    return s;
}

constexpr int kIterations = 20000;

} // namespace

TEST_CASE("LfToCrLf: known vectors")
{
    CHECK_BYTES(ToCrLf(""), "");
    CHECK_BYTES(ToCrLf("abc"), "abc");
    CHECK_BYTES(ToCrLf("\n"), "\r\n");
    CHECK_BYTES(ToCrLf("a\nb\n"), "a\r\nb\r\n");
    CHECK_BYTES(ToCrLf("a\r\nb"), "a\r\nb");
    CHECK_BYTES(ToCrLf("\r"), "\r");
    CHECK_BYTES(ToCrLf("\n\n"), "\r\n\r\n");
    CHECK_BYTES(ToCrLf("\r\r\n"), "\r\r\n");
    CHECK_BYTES(ToCrLf("\n\r"), "\r\n\r");
    CHECK_BYTES(ToCrLf(std::string("\0\n", 2)), std::string("\0\r\n", 3));
}

TEST_CASE("LfToCrLf: CR at a chunk boundary is not doubled")
{
    LfToCrLf conv;
    std::vector<char> out;
    conv.Convert("a\r", 2, out);
    conv.Convert("\nb", 2, out);
    CHECK_BYTES(std::string(out.begin(), out.end()), "a\r\nb");
}

TEST_CASE("LfToCrLf: worst case doubles without touching the input")
{
    const std::string in(65536, '\n');
    const std::string copy = in;
    LfToCrLf conv;
    std::vector<char> out;
    const size_t n = conv.Convert(in.data(), in.size(), out);
    CHECK_EQ(n, 2 * in.size());
    CHECK_EQ(out.size(), 2 * in.size());
    CHECK(in == copy);
}

TEST_CASE("CrLfToLf: known vectors")
{
    CHECK_BYTES(ToLf(""), "");
    CHECK_BYTES(ToLf("abc"), "abc");
    CHECK_BYTES(ToLf("\r\n"), "\n");
    CHECK_BYTES(ToLf("a\r\nb\r\n"), "a\nb\n");
    CHECK_BYTES(ToLf("a\nb"), "a\nb");
    CHECK_BYTES(ToLf("\r"), "\r");
    CHECK_BYTES(ToLf("a\rb"), "a\rb");
    CHECK_BYTES(ToLf("\r\r\n"), "\r\n");
    CHECK_BYTES(ToLf("\r\r"), "\r\r");
    CHECK_BYTES(ToLf("\n\r"), "\n\r");
}

TEST_CASE("CrLfToLf: CRLF split across chunks is still one line break")
{
    CrLfToLf conv;
    std::vector<char> out;
    CHECK_EQ(conv.Convert("line\r", 5, out), size_t{4});
    CHECK_EQ(conv.Convert("\nnext", 5, out), size_t{5});
    CHECK_EQ(conv.Finish(out), size_t{0});
    CHECK_BYTES(std::string(out.begin(), out.end()), "line\nnext");
}

TEST_CASE("CrLfToLf: trailing CR is emitted by Finish")
{
    CrLfToLf conv;
    std::vector<char> out;
    CHECK_EQ(conv.Convert("end\r", 4, out), size_t{3});
    CHECK_EQ(conv.Finish(out), size_t{1});
    CHECK_BYTES(std::string(out.begin(), out.end()), "end\r");
    CHECK_EQ(conv.Finish(out), size_t{0});
}

TEST_CASE("property: chunked conversion equals whole conversion")
{
    test::Rng rng(0x5F7Bull);
    for (int i = 0; i < kIterations; ++i) {
        const std::string in = RandomText(rng, 64);
        const auto chunks = RandomChunks(in, rng);

        LfToCrLf down;
        std::vector<char> downOut;
        CrLfToLf up;
        std::vector<char> upOut;
        for (const auto& c : chunks) {
            down.Convert(c.data(), c.size(), downOut);
            up.Convert(c.data(), c.size(), upOut);
        }
        up.Finish(upOut);

        CHECK_BYTES(std::string(downOut.begin(), downOut.end()), ToCrLf(in));
        CHECK_BYTES(std::string(upOut.begin(), upOut.end()), ToLf(in));
    }
}

TEST_CASE("property: Count predicts Convert exactly under any chunking")
{
    test::Rng rng(0xC0FFEEull);
    for (int i = 0; i < kIterations; ++i) {
        const std::string in = RandomText(rng, 64);
        CrLfToLf counter;
        size_t counted = 0;
        for (const auto& c : RandomChunks(in, rng))
            counted += counter.Count(c.data(), c.size());
        counted += counter.FinishCount();
        CHECK_EQ(counted, ToLf(in).size());
    }
}

TEST_CASE("property: LfToCrLf output has no bare LF and stays within 2x")
{
    test::Rng rng(0xBADC0DEull);
    for (int i = 0; i < kIterations; ++i) {
        const std::string in = RandomText(rng, 64);
        const std::string out = ToCrLf(in);
        CHECK(out.size() >= in.size());
        CHECK(out.size() <= 2 * in.size());
        for (size_t k = 0; k < out.size(); ++k) {
            if (out[k] == '\n')
                CHECK(k > 0 && out[k - 1] == '\r');
        }
    }
}

TEST_CASE("property: download then upload restores text without CRLF pairs")
{
    test::Rng rng(0x1234ull);
    for (int i = 0; i < kIterations; ++i) {
        std::string in = RandomText(rng, 64);
        for (size_t k = in.find("\r\n"); k != std::string::npos; k = in.find("\r\n"))
            in.erase(k, 1);
        CHECK_BYTES(ToLf(ToCrLf(in)), in);
    }
}
