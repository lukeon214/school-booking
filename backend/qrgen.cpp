#include <iostream>
#include <vector>
#include <fstream>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <limits>
#include <cstring>

class QRcode {
public:
    enum ECCLevel { L = 0, M = 1, Q = 2, H = 3 };
    const int modules;
private:
    const int version;
    const ECCLevel ecc_level;
    int width;
    int height;
    std::vector<std::vector<bool>> reserved;
    int exp[256];
    int log[256];
    // Per-version config
    struct BlockConfig {
        int ec_per_block;
        int group1_blocks;
        int data_group1;
        int group2_blocks;
        int data_group2;
    };
    static const BlockConfig configs[4][41];
    static BlockConfig getBlockConfig(int ver, int lev) {
        if (ver < 1 || ver > 40) throw std::invalid_argument("Version must be 1-40");
        if (lev < 0 || lev > 3) throw std::invalid_argument("ECC level must be 0-3 (L-H)");
        return configs[lev][ver];
    }
    BlockConfig getBlockConfig() const {
        return getBlockConfig(version, static_cast<int>(ecc_level));
    }
    void initGaloisField() {
        int x = 1;
        for (int i = 0; i < 255; i++) {
            exp[i] = x;
            log[x] = i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11D;
        }
        exp[255] = exp[0];
    }
    int multiply(int a, int b) {
        if (a == 0 || b == 0) return 0;
        return exp[(log[a] + log[b]) % 255];
    }
    std::vector<int> getAlignmentPositions() {
        if (version == 1) return {};
        int k = (version / 7) + 2;
        std::vector<int> pos(k);
        int p1 = 6;
        int pk = modules - 7;
        if (k == 2) {
            pos[0] = p1;
            pos[1] = pk;
        }
        else {
            int interval = pk - p1;
            int S = (interval + k - 2) / (k - 1);
            if (S % 2 != 0) S++;
            pos[k - 1] = pk;
            for (int i = k - 2; i > 0; i--) {
                pos[i] = pos[i + 1] - S;
            }
            pos[0] = p1;
        }
        return pos;
    }
    int count_pattern(const std::string& s, const std::string& pat) {
        int count = 0;
        size_t pos = 0;
        while ((pos = s.find(pat, pos)) != std::string::npos) {
            count++;
            pos += 1;
        }
        return count;
    }
    int computePenalty(const std::vector<std::vector<bool>>& mat) {
        int score = 0;
        // Rule 1: Runs of same color horizontal
        for (int y = 0; y < height; y++) {
            int run = 1;
            bool prev = mat[y][0];
            for (int x = 1; x < width; x++) {
                if (mat[y][x] == prev) {
                    run++;
                }
                else {
                    if (run >= 5) score += 3 + (run - 5);
                    run = 1;
                    prev = mat[y][x];
                }
            }
            if (run >= 5) score += 3 + (run - 5);
        }
        // Vertical
        for (int x = 0; x < width; x++) {
            int run = 1;
            bool prev = mat[0][x];
            for (int y = 1; y < height; y++) {
                if (mat[y][x] == prev) {
                    run++;
                }
                else {
                    if (run >= 5) score += 3 + (run - 5);
                    run = 1;
                    prev = mat[y][x];
                }
            }
            if (run >= 5) score += 3 + (run - 5);
        }
        // Rule 2: 2x2 blocks
        for (int y = 0; y < height - 1; y++) {
            for (int x = 0; x < width - 1; x++) {
                bool c = mat[y][x];
                if (c == mat[y][x + 1] && c == mat[y + 1][x] && c == mat[y + 1][x + 1]) score += 3;
            }
        }
        // Rule 3: Special patterns
        std::string pat1 = "10111010000";
        std::string pat2 = "00001011101";
        for (int y = 0; y < height; y++) {
            std::string row_str = "";
            for (int x = 0; x < width; x++) row_str += mat[y][x] ? '1' : '0';
            score += 40 * (count_pattern(row_str, pat1) + count_pattern(row_str, pat2));
        }
        for (int x = 0; x < width; x++) {
            std::string col_str = "";
            for (int y = 0; y < height; y++) col_str += mat[y][x] ? '1' : '0';
            score += 40 * (count_pattern(col_str, pat1) + count_pattern(col_str, pat2));
        }
        // Rule 4: Dark ratio
        int dark = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (mat[y][x]) dark++;
            }
        }
        double ratio = 100.0 * dark / (modules * modules);
        int k = static_cast<int>(std::floor(std::abs(ratio - 50.0) / 5.0));
        score += k * 10;
        return score;
    }
public:
    std::vector<std::vector<bool>> pixels;
    QRcode(int ver, ECCLevel ecc = L) : version(ver), ecc_level(ecc), modules((ver - 1) * 4 + 21), width(modules), height(modules),
        pixels(height, std::vector<bool>(width, false)),
        reserved(height, std::vector<bool>(width, false)) {
        if (version < 1 || version > 40) throw std::invalid_argument("Version must be 1-40");
        initGaloisField();
    }
    void setPixel(int x, int y, bool isBlack, bool markReserved = false, bool force = false) {
        if (x >= 0 && x < width && y >= 0 && y < height) {
            if (!reserved[y][x] || force) {
                pixels[y][x] = isBlack;
                if (markReserved) reserved[y][x] = true;
            }
        }
    }
    void finderPatterns() {
        auto markFinder = [&](int startX, int startY) {
            for (int dy = 0; dy < 8; dy++) {
                for (int dx = 0; dx < 8; dx++) {
                    int curX = startX + dx;
                    int curY = startY + dy;
                    if (curX >= width || curY >= height || curX < 0 || curY < 0) continue;
                    if (dx < 7 && dy < 7) {
                        bool isBlack = (dx == 0 || dx == 6 || dy == 0 || dy == 6 || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
                        setPixel(curX, curY, isBlack, true);
                    }
                    else {
                        setPixel(curX, curY, false, true);
                    }
                }
            }
            };
        markFinder(0, 0);
        markFinder(width - 7, 0);
        markFinder(0, height - 7);
    }
    void alignmentPatterns() {
        std::vector<int> pos = getAlignmentPositions();
        if (pos.empty()) return;
        for (int cx : pos) {
            for (int cy : pos) {
                if ((cx < 10 && cy < 10) ||
                    (cx > modules - 10 && cy < 10) ||
                    (cx < 10 && cy > modules - 10)) continue;
                for (int dy = -2; dy <= 2; dy++) {
                    for (int dx = -2; dx <= 2; dx++) {
                        int maxDist = std::max(std::abs(dx), std::abs(dy));
                        bool isBlack = (maxDist == 2 || maxDist == 0);
                        setPixel(cx + dx, cy + dy, isBlack, true);
                    }
                }
            }
        }
    }
    void timingStrips() {
        const int N = modules;
        for (int i = 8; i <= N - 9; i++) {
            setPixel(i, 6, (i % 2 == 0), true);
            setPixel(6, i, (i % 2 == 0), true);
        }
    }
    void applyMask(std::vector<std::vector<bool>>& mat, int mask) {
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (reserved[y][x]) continue;
                bool invert = false;
                switch (mask) {
                case 0: invert = (x + y) % 2 == 0; break;
                case 1: invert = y % 2 == 0; break;
                case 2: invert = x % 3 == 0; break;
                case 3: invert = (x + y) % 3 == 0; break;
                case 4: invert = ((y / 2) + (x / 3)) % 2 == 0; break;
                case 5: invert = (x * y) % 2 + (x * y) % 3 == 0; break;
                case 6: invert = ((x * y) % 2 + (x * y) % 3) % 2 == 0; break;
                case 7: invert = ((x + y) % 2 + (x * y) % 3) % 2 == 0; break;
                }
                if (invert) mat[y][x] = !mat[y][x];
            }
        }
    }
    int chooseBestMask() {
        int min_score = std::numeric_limits<int>::max();
        int best_mask = 0;
        for (int mask = 0; mask < 8; mask++) {
            auto mat = pixels;
            applyMask(mat, mask);
            auto fmt = getFormatBits(mask);
            placeFormat(mat, fmt);
            int score = computePenalty(mat);
            if (score < min_score) {
                min_score = score;
                best_mask = mask;
            }
        }
        return best_mask;
    }
    unsigned int computeVersionBCH(int ver) {
        unsigned int polynomial = 0x1F25U;
        unsigned int remainder = static_cast<unsigned int>(ver) << 12U;
        for (int i = 17; i >= 12; --i) {
            if (remainder & (1U << static_cast<unsigned int>(i))) {
                remainder ^= polynomial << static_cast<unsigned int>(i - 12);
            }
        }
        return remainder & 0xFFFU;
    }
    std::vector<bool> getFormatBits(int mask) {
        int ecc_code;
        switch (ecc_level) {
        case L: ecc_code = 0b01; break;
        case M: ecc_code = 0b00; break;
        case Q: ecc_code = 0b11; break;
        case H: ecc_code = 0b10; break;
        default: throw std::invalid_argument("Invalid ECC level");
        }
        int data = (ecc_code << 3) | mask;
        int gen = 0x537;
        int poly = data << 10;
        for (int i = 14; i >= 10; --i) {
            if (poly & (1 << i)) {
                poly ^= gen << (i - 10);
            }
        }
        int ec = poly & 0x3ff;
        int format = (data << 10) | ec;
        format ^= 0x5412;
        std::vector<bool> bits;
        for (int i = 14; i >= 0; --i) {
            bits.push_back((format >> i) & 1);
        }
        return bits;
    }
    void reserveVersionAreas() {
        if (version < 7) return;
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 3; j++) {
                setPixel(i, height - 11 + j, false, true); // Bottom left
                setPixel(height - 11 + j, i, false, true); // Top right
            }
        }
    }
    void placeVersionInfo() {
        if (version < 7) return;
        unsigned int bch = computeVersionBCH(version);
        unsigned int version_shifted = static_cast<unsigned int>(version) << 12U;
        unsigned int version_bits = (version_shifted & 0x3F000U) | (bch & 0xFFFU);
        // Bottom-left: bit 0 (LSB) at top-right of block, bit 17 at bottom-left
        const int bottom_y_base = height - 11;
        for (int bit_idx = 0; bit_idx < 18; ++bit_idx) {
            int col = 5 - (bit_idx / 3); // right to left
            int row = bit_idx % 3; // top to bottom
            bool value = (version_bits >> bit_idx) & 1U; // LSB = bit_idx 0
            int y = bottom_y_base + row;
            int x = col;
            setPixel(x, y, value, true, true);
        }
        // Top-right: bit 0 (LSB) at bottom-right, bit 17 at top-left
        const int top_x_base = modules - 11;
        int bit_idx = 0;
        for (int row = 0; row < 6; ++row) {
            for (int col = 0; col < 3; ++col) {
                bool value = (version_bits >> bit_idx) & 1U;
                int x = top_x_base + col;
                int y = row;
                setPixel(x, y, value, true, true);
                ++bit_idx;
            }
        }
    }
    void placeFormat(std::vector<std::vector<bool>>& mat, const std::vector<bool>& fmt) {
        for (int i = 0; i <= 5; i++) mat[8][i] = fmt[i];
        mat[8][7] = fmt[6];
        mat[8][8] = fmt[7];
        mat[7][8] = fmt[8];
        for (int i = 9; i <= 14; i++) mat[14 - i][8] = fmt[i];
        for (int i = 0; i <= 6; i++) mat[height - 1 - i][8] = fmt[i];
        for (int i = 7; i <= 14; i++) mat[8][width - 8 + (i - 7)] = fmt[i];
    }
    void specialPixel() {
        setPixel(8, modules - 8, true, true, true);
    }
    std::vector<bool> buildBitstream(std::string message) {
        BlockConfig config = getBlockConfig();
        int total_data_codewords = config.group1_blocks * config.data_group1 + config.group2_blocks * config.data_group2;
        int max_data_bits = total_data_codewords * 8;
        int len = message.length();
        int len_bits = (version <= 9) ? 8 : 16;
        if (4 + len_bits + len * 8 > max_data_bits) {
            throw std::invalid_argument("Message too long for this QR version and ECC level");
        }
        std::vector<bool> bits = { 0, 1, 0, 0 }; // Mode: byte (0100)
        for (int i = len_bits - 1; i >= 0; --i) {
            bits.push_back((len >> i) & 1);
        }
        for (char c : message) {
            for (int i = 7; i >= 0; --i) {
                bits.push_back((c >> i) & 1);
            }
        }
        int current_bits = bits.size();
        int remaining_bits = max_data_bits - current_bits;
        int term_bits = std::min(4, remaining_bits);
        for (int i = 0; i < term_bits; ++i) {
            bits.push_back(0);
        }
        current_bits += term_bits;
        int pad_to_byte = (8 - (current_bits % 8)) % 8;
        for (int i = 0; i < pad_to_byte; ++i) {
            bits.push_back(0);
        }
        current_bits += pad_to_byte;
        int current_codewords = current_bits / 8;
        bool use_236 = true;
        while (current_codewords < total_data_codewords) {
            int pad_cw = use_236 ? 236 : 17;
            for (int j = 7; j >= 0; --j) {
                bits.push_back((pad_cw >> j) & 1);
            }
            use_236 = !use_236;
            ++current_codewords;
        }
        if (bits.size() != max_data_bits) {
            throw std::runtime_error("Bitstream size mismatch");
        }
        return bits;
    }
    void appendEC(std::vector<bool>& bits) {
        BlockConfig config = getBlockConfig();
        int total_data_codewords = config.group1_blocks * config.data_group1 + config.group2_blocks * config.data_group2;
        int total_blocks = config.group1_blocks + config.group2_blocks;
        std::vector<int> data_codewords(total_data_codewords);
        for (size_t i = 0; i < bits.size(); i += 8) {
            int cw = 0;
            for (int j = 0; j < 8; ++j) {
                cw = (cw << 1) | bits[i + j];
            }
            data_codewords[i / 8] = cw;
        }
        std::vector<std::vector<int>> blocks_data(total_blocks);
        int offset = 0;
        for (int b = 0; b < config.group1_blocks; ++b) {
            blocks_data[b].resize(config.data_group1);
            for (int j = 0; j < config.data_group1; ++j) {
                blocks_data[b][j] = data_codewords[offset++];
            }
        }
        for (int b = config.group1_blocks; b < total_blocks; ++b) {
            blocks_data[b].resize(config.data_group2);
            for (int j = 0; j < config.data_group2; ++j) {
                blocks_data[b][j] = data_codewords[offset++];
            }
        }
        std::vector<std::vector<int>> blocks_ec(total_blocks);
        for (int b = 0; b < total_blocks; ++b) {
            blocks_ec[b] = generateEC(blocks_data[b], config.ec_per_block);
        }
        std::vector<int> interleaved;
        // Interleave data
        int max_data_per_block = (config.group2_blocks > 0 ? config.data_group2 : config.data_group1);
        for (int j = 0; j < max_data_per_block; ++j) {
            for (int b = 0; b < total_blocks; ++b) {
                int block_data_size = (b < config.group1_blocks ? config.data_group1 : config.data_group2);
                if (j < block_data_size) {
                    interleaved.push_back(blocks_data[b][j]);
                }
            }
        }
        // Interleave EC
        for (int j = 0; j < config.ec_per_block; ++j) {
            for (int b = 0; b < total_blocks; ++b) {
                interleaved.push_back(blocks_ec[b][j]);
            }
        }
        bits.clear();
        for (int cw : interleaved) {
            for (int j = 7; j >= 0; --j) {
                bits.push_back((cw >> j) & 1);
            }
        }
    }
    std::vector<int> generateEC(const std::vector<int>& dataCodewords, int ecCount) {
        std::vector<int> gen = { 1 };
        for (int i = 0; i < ecCount; ++i) {
            int r = exp[i];
            std::vector<int> product(gen.size() + 1, 0);
            for (size_t j = 0; j < gen.size(); ++j) {
                product[j] ^= multiply(gen[j], r);
            }
            for (size_t j = 0; j < gen.size(); ++j) {
                product[j + 1] ^= gen[j];
            }
            gen = product;
        }
        std::reverse(gen.begin(), gen.end());
        std::vector<int> msg = dataCodewords;
        msg.resize(msg.size() + ecCount, 0);
        for (size_t i = 0; i < dataCodewords.size(); ++i) {
            int lead = msg[i];
            if (lead == 0) continue;
            for (int j = 0; j <= ecCount; ++j) {
                msg[i + j] ^= multiply(gen[j], lead);
            }
        }
        return std::vector<int>(msg.end() - ecCount, msg.end());
    }
    void reserveFormatAreas() {
        for (int y = 0; y < 9; y++) setPixel(8, y, false, true);
        for (int y = height - 7; y < height; y++) setPixel(8, y, false, true);
        for (int x = 0; x < 9; x++) setPixel(x, 8, false, true);
        for (int x = width - 8; x < width; x++) setPixel(x, 8, false, true);
        setPixel(8, modules - 8, false, true); // Reserve dark but set later
    }
    void reserveFunctionalAreas() {
        const int N = modules;
        for (int i = 0; i <= 8; i++) {
            setPixel(8, i, false, true);
            setPixel(i, 8, false, true);
        }
        for (int i = 0; i <= 8; i++) {
            setPixel(N - 8, i, false, true);
        }
        for (int i = N - 8; i < N; i++) {
            setPixel(i, 8, false, true);
        }
        for (int i = N - 8; i < N; i++) {
            setPixel(8, i, false, true);
        }
        for (int i = 0; i <= 8; i++) {
            setPixel(i, N - 8, false, true);
        }
        setPixel(8, N - 8, false, true);
    }
    void placeData(const std::vector<bool>& bitStream) {
        int N = modules;
        int bitIndex = 0;
        int direction = -1;
        int x = N - 1;
        int y = N - 1;
        while (x > 0) {
            if (x == 6) x--;
            for (int i = 0; i < 2; i++) {
                int currentX = x - i;
                if (currentX >= 0 && !reserved[y][currentX]) {
                    bool bit = (bitIndex < bitStream.size()) ? bitStream[bitIndex++] : false;
                    setPixel(currentX, y, bit);
                }
            }
            y += direction;
            if (y < 0 || y >= N) {
                direction = -direction;
                x -= 2;
                y += direction;
            }
        }
    }
    std::string extractPlacedData() {
        std::string extracted = "";
        int N = modules;
        int direction = -1;
        int x = N - 1;
        int y = N - 1;
        int count = 0;
        while (x > 0) {
            if (x == 6) x--;
            for (int i = 0; i < 2; i++) {
                int currentX = x - i;
                if (currentX >= 0 && !reserved[y][currentX]) {
                    extracted += pixels[y][currentX] ? '1' : '0';
                    count++;
                    if (count % 8 == 0) extracted += " ";
                }
            }
            y += direction;
            if (y < 0 || y >= N) {
                direction = -direction;
                x -= 2;
                y += direction;
            }
        }
        return extracted;
    }
    void writeToPPM(const std::string& filename, int scale = 10) {
        std::ofstream img(filename, std::ios::binary);
        img << "P6\n" << width * scale << " " << height * scale << "\n255\n";
        for (int y = 0; y < height; y++) {
            for (int row = 0; row < scale; row++) {
                for (int x = 0; x < width; x++) {
                    for (int col = 0; col < scale; col++) {
                        char color = pixels[y][x] ? 0 : (char)255;
                        img.put(color);
                        img.put(color);
                        img.put(color);
                    }
                }
            }
        }
        img.close();
    }
    void writeToRaw(const std::string& filename, int scale = 10) {
        std::ofstream img(filename, std::ios::binary);
        if (!img) {
            throw std::runtime_error("Cannot open output file");
        }
        for (int y = 0; y < height; y++) {
            for (int row = 0; row < scale; row++) {
                for (int x = 0; x < width; x++) {
                    for (int col = 0; col < scale; col++) {
                        unsigned char color = pixels[y][x] ? 0 : 255;
                        img.put(color);
                        img.put(color);
                        img.put(color);
                    }
                }
            }
        }
        img.close();
        if (!img.good()) {
            throw std::runtime_error("Error writing to output file");
        }
    }
    static int findMinimalVersion(int message_length, ECCLevel ecc) {
        if (message_length < 0) throw std::invalid_argument("Invalid message length");
        for (int v = 1; v <= 40; ++v) {
            BlockConfig config = getBlockConfig(v, static_cast<int>(ecc));
            int total_data_codewords = config.group1_blocks * config.data_group1 + config.group2_blocks * config.data_group2;
            int max_data_bits = total_data_codewords * 8;
            int len_bits = (v <= 9) ? 8 : 16;
            long long payload = 4LL + len_bits + 8LL * message_length;
            if (payload > max_data_bits) continue;
            int remaining = max_data_bits - static_cast<int>(payload);
            int term = std::min(4, remaining);
            long long current = payload + term;
            int pad_bit = (8 - (static_cast<int>(current) % 8)) % 8;
            long long total = current + pad_bit;
            if (total <= max_data_bits) {
                return v;
            }
        }
        throw std::invalid_argument("Message too long for any QR version (1-40) at this ECC level");
    }
};

const QRcode::BlockConfig QRcode::configs[4][41] = {
    // L (0)
    {
        {}, // 0
        {7, 1, 19, 0, 0}, // 1
        {10, 1, 34, 0, 0}, // 2
        {15, 1, 55, 0, 0}, // 3
        {20, 1, 80, 0, 0}, // 4
        {26, 1, 108, 0, 0}, // 5
        {18, 2, 68, 0, 0}, // 6
        {20, 2, 78, 0, 0}, // 7
        {24, 2, 97, 0, 0}, // 8
        {30, 2, 116, 0, 0}, // 9
        {18, 2, 68, 2, 69}, // 10
        {20, 4, 81, 0, 0}, // 11
        {24, 2, 92, 2, 93}, // 12
        {26, 4, 107, 0, 0}, // 13
        {30, 3, 115, 1, 116}, // 14
        {22, 5, 87, 1, 88}, // 15
        {24, 5, 98, 1, 99}, // 16
        {28, 1, 107, 5, 108}, // 17
        {30, 5, 120, 1, 121}, // 18
        {28, 3, 113, 4, 114}, // 19
        {28, 3, 107, 5, 108}, // 20
        {28, 4, 116, 4, 117}, // 21
        {28, 2, 111, 7, 112}, // 22
        {30, 4, 121, 5, 122}, // 23
        {30, 6, 117, 4, 118}, // 24
        {26, 8, 106, 4, 107}, // 25
        {28, 10, 114, 2, 115}, // 26
        {30, 8, 122, 4, 123}, // 27
        {30, 3, 117, 10, 118}, // 28
        {30, 7, 116, 7, 117}, // 29
        {30, 5, 115, 10, 116}, // 30
        {30, 13, 115, 3, 116}, // 31
        {30, 17, 115, 0, 0}, // 32
        {30, 17, 115, 1, 116}, // 33
        {30, 13, 115, 6, 116}, // 34
        {30, 12, 121, 7, 122}, // 35
        {30, 6, 121, 14, 122}, // 36
        {30, 17, 122, 4, 123}, // 37
        {30, 4, 122, 18, 123}, // 38
        {30, 20, 117, 4, 118}, // 39
        {30, 19, 118, 6, 119} // 40
    },
    // M (1)
    {
        {}, // 0
        {10, 1, 16, 0, 0}, // 1
        {16, 1, 28, 0, 0}, // 2
        {26, 1, 44, 0, 0}, // 3
        {18, 2, 32, 0, 0}, // 4
        {24, 2, 43, 0, 0}, // 5
        {16, 4, 27, 0, 0}, // 6
        {18, 4, 31, 0, 0}, // 7
        {22, 2, 38, 2, 39}, // 8
        {22, 3, 36, 2, 37}, // 9
        {26, 4, 43, 1, 44}, // 10
        {30, 1, 50, 4, 51}, // 11
        {22, 6, 36, 2, 37}, // 12
        {22, 8, 37, 1, 38}, // 13
        {24, 4, 40, 5, 41}, // 14
        {24, 5, 41, 5, 42}, // 15
        {28, 7, 45, 3, 46}, // 16
        {28, 10, 46, 1, 47}, // 17
        {26, 9, 43, 4, 44}, // 18
        {26, 3, 44, 11, 45}, // 19
        {26, 3, 41, 13, 42}, // 20
        {26, 17, 42, 0, 0}, // 21
        {28, 17, 46, 0, 0}, // 22
        {28, 4, 47, 14, 48}, // 23
        {28, 6, 45, 14, 46}, // 24
        {28, 8, 47, 13, 48}, // 25
        {28, 19, 46, 4, 47}, // 26
        {28, 22, 45, 3, 46}, // 27
        {28, 3, 45, 23, 46}, // 28
        {28, 21, 45, 7, 46}, // 29
        {28, 19, 47, 10, 48}, // 30
        {28, 2, 46, 29, 47}, // 31
        {28, 10, 46, 23, 47}, // 32
        {28, 14, 46, 21, 47}, // 33
        {28, 14, 46, 23, 47}, // 34
        {28, 12, 47, 26, 48}, // 35
        {28, 6, 47, 34, 48}, // 36
        {28, 29, 46, 14, 47}, // 37
        {28, 13, 46, 32, 47}, // 38
        {28, 40, 47, 7, 48}, // 39
        {28, 18, 47, 31, 48} // 40
    },
    // Q (2)
    {
        {}, // 0
        {13, 1, 13, 0, 0}, // 1
        {22, 1, 22, 0, 0}, // 2
        {18, 2, 17, 0, 0}, // 3
        {26, 2, 24, 0, 0}, // 4
        {18, 2, 15, 2, 16}, // 5
        {24, 4, 19, 0, 0}, // 6
        {18, 2, 14, 4, 15}, // 7
        {22, 4, 18, 2, 19}, // 8
        {20, 4, 16, 4, 17}, // 9
        {24, 6, 19, 2, 20}, // 10
        {28, 4, 22, 4, 23}, // 11
        {26, 4, 20, 6, 21}, // 12
        {24, 8, 20, 4, 21}, // 13
        {20, 11, 16, 5, 17}, // 14
        {30, 5, 24, 7, 25}, // 15
        {24, 15, 19, 2, 20}, // 16
        {28, 1, 22, 15, 23}, // 17
        {28, 17, 22, 1, 23}, // 18
        {26, 17, 21, 4, 22}, // 19
        {30, 15, 24, 5, 25}, // 20
        {28, 17, 22, 6, 23}, // 21
        {30, 7, 24, 16, 25}, // 22
        {30, 11, 24, 14, 25}, // 23
        {30, 11, 24, 16, 25}, // 24
        {30, 7, 24, 22, 25}, // 25
        {28, 28, 22, 6, 23}, // 26
        {30, 8, 23, 26, 24}, // 27
        {30, 4, 24, 31, 25}, // 28
        {30, 1, 23, 37, 24}, // 29
        {30, 15, 24, 25, 25}, // 30
        {30, 42, 24, 1, 25}, // 31
        {30, 10, 24, 35, 25}, // 32
        {30, 29, 24, 19, 25}, // 33
        {30, 44, 24, 7, 25}, // 34
        {30, 39, 24, 14, 25}, // 35
        {30, 46, 24, 10, 25}, // 36
        {30, 49, 24, 10, 25}, // 37
        {30, 48, 24, 14, 25}, // 38
        {30, 43, 24, 22, 25}, // 39
        {30, 34, 24, 34, 25} // 40
    },
    // H (3)
    {
        {}, // 0
        {17, 1, 9, 0, 0}, // 1
        {28, 1, 16, 0, 0}, // 2
        {22, 2, 13, 0, 0}, // 3
        {16, 4, 9, 0, 0}, // 4
        {22, 2, 11, 2, 12}, // 5
        {28, 4, 15, 0, 0}, // 6
        {26, 4, 13, 1, 14}, // 7
        {26, 4, 14, 2, 15}, // 8
        {24, 4, 12, 4, 13}, // 9
        {28, 6, 15, 2, 16}, // 10
        {24, 3, 12, 8, 13}, // 11
        {28, 7, 14, 4, 15}, // 12
        {22, 12, 11, 4, 12}, // 13
        {24, 11, 12, 5, 13}, // 14
        {24, 11, 12, 7, 13}, // 15
        {30, 3, 15, 13, 16}, // 16
        {28, 2, 14, 17, 15}, // 17
        {28, 2, 14, 19, 15}, // 18
        {26, 9, 13, 16, 14}, // 19
        {28, 15, 15, 10, 16}, // 20
        {30, 19, 16, 6, 17}, // 21
        {24, 34, 13, 0, 0}, // 22
        {30, 16, 15, 14, 16}, // 23
        {30, 30, 16, 2, 17}, // 24
        {30, 22, 15, 13, 16}, // 25
        {30, 33, 16, 4, 17}, // 26
        {30, 12, 15, 28, 16}, // 27
        {30, 11, 15, 31, 16}, // 28
        {30, 19, 15, 26, 16}, // 29
        {30, 23, 15, 25, 16}, // 30
        {30, 23, 15, 28, 16}, // 31
        {30, 19, 15, 35, 16}, // 32
        {30, 11, 15, 46, 16}, // 33
        {30, 59, 16, 1, 17}, // 34
        {30, 22, 15, 41, 16}, // 35
        {30, 2, 15, 64, 16}, // 36
        {30, 24, 15, 46, 16}, // 37
        {30, 42, 15, 32, 16}, // 38
        {30, 10, 15, 67, 16}, // 39
        {30, 20, 15, 61, 16} // 40
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: qrgen.exe <message> <ecc_level> <output_file> [version]\n";
        std::cerr << "ecc_level: L, M, Q, H\n";
        std::cerr << "version: optional, auto if omitted\n";
        return 1;
    }

    try {
        std::string msg = argv[1];
        std::string ecc_str = argv[2];
        std::string output = argv[3];
        QRcode::ECCLevel ecc;
        if (ecc_str == "L") ecc = QRcode::L;
        else if (ecc_str == "M") ecc = QRcode::M;
        else if (ecc_str == "Q") ecc = QRcode::Q;
        else if (ecc_str == "H") ecc = QRcode::H;
        else throw std::invalid_argument("Invalid ECC level");

        int ver = (argc > 4) ? std::stoi(argv[4]) : QRcode::findMinimalVersion(static_cast<int>(msg.length()), ecc);

        QRcode qr(ver, ecc);
        qr.finderPatterns();
        qr.timingStrips();
        qr.alignmentPatterns();
        qr.reserveFunctionalAreas();
        qr.reserveVersionAreas();
        qr.reserveFormatAreas();
        qr.specialPixel();
        std::vector<bool> data = qr.buildBitstream(msg);
        qr.appendEC(data);
        qr.placeData(data);
        qr.placeVersionInfo();
        int best_mask = qr.chooseBestMask();
        qr.applyMask(qr.pixels, best_mask);
        auto fmt = qr.getFormatBits(best_mask);
        qr.placeFormat(qr.pixels, fmt);

        // Output dimensions to stdout for Node.js to parse
        int scaled_size = qr.modules * 10;  // Assuming scale=10, QR is square
        std::cout << "DIM " << scaled_size << std::endl;

        qr.writeToRaw(output);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}