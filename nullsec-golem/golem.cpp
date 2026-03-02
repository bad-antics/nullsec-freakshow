// ──────────────────────────────────────────────────────────
// 🗿 nullsec-golem — Memory-Mapped File Hasher (C++)
// Part of the nullsec freakshow suite.
//
// Uses mmap for zero-copy file I/O and SHA-256 hashing.
// Fast parallel directory hashing with std::thread.
// ──────────────────────────────────────────────────────────

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <cstring>
#include <cstdint>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace fs = std::filesystem;

static const char* VERSION = "1.0.0";

// ── SHA-256 implementation ──────────────────────────────

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t sig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
inline uint32_t sig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
inline uint32_t gam0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x>>3); }
inline uint32_t gam1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x>>10); }

struct SHA256 {
    uint32_t h[8];
    uint8_t  buf[64];
    size_t   buflen;
    uint64_t total;

    SHA256() { reset(); }

    void reset() {
        h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
        h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
        buflen = 0; total = 0;
    }

    void transform(const uint8_t* block) {
        uint32_t w[64], a, b, c, d, e, f, g, hh;
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)block[i*4]<<24 | (uint32_t)block[i*4+1]<<16 |
                   (uint32_t)block[i*4+2]<<8 | block[i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = gam1(w[i-2]) + w[i-7] + gam0(w[i-15]) + w[i-16];

        a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4]; f=h[5]; g=h[6]; hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sig1(e) + ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const uint8_t* data, size_t len) {
        total += len;
        while (len > 0) {
            size_t space = 64 - buflen;
            size_t take = std::min(len, space);
            memcpy(buf + buflen, data, take);
            buflen += take;
            data += take;
            len -= take;
            if (buflen == 64) { transform(buf); buflen = 0; }
        }
    }

    std::string final_hex() {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (buflen != 56) update(&pad, 1);
        uint8_t len_be[8];
        for (int i = 7; i >= 0; i--) { len_be[i] = bits & 0xFF; bits >>= 8; }
        update(len_be, 8);

        char hex[65];
        for (int i = 0; i < 8; i++)
            snprintf(hex + i*8, 9, "%08x", h[i]);
        hex[64] = 0;
        return std::string(hex);
    }
};

// ── mmap hashing ────────────────────────────────────────

struct FileHash {
    std::string path;
    std::string hash;
    size_t      size;
    bool        error;
    std::string errmsg;
};

FileHash hash_file_mmap(const std::string& path) {
    FileHash result;
    result.path = path;
    result.error = false;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        result.error = true;
        result.errmsg = strerror(errno);
        return result;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        result.error = true;
        result.errmsg = "not a regular file";
        return result;
    }

    result.size = st.st_size;
    SHA256 sha;

    if (st.st_size == 0) {
        result.hash = sha.final_hex();
        close(fd);
        return result;
    }

    void* mapped = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED) {
        result.error = true;
        result.errmsg = strerror(errno);
        return result;
    }

    // Advise sequential access for performance
    madvise(mapped, st.st_size, MADV_SEQUENTIAL);

    sha.update(reinterpret_cast<const uint8_t*>(mapped), st.st_size);
    result.hash = sha.final_hex();

    munmap(mapped, st.st_size);
    return result;
}

// ── Worker pool ─────────────────────────────────────────

class WorkerPool {
    std::queue<std::string>   tasks;
    std::mutex                mtx;
    std::vector<FileHash>     results;
    std::mutex                res_mtx;
    std::vector<std::thread>  threads;
    bool                      done = false;

public:
    void add_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mtx);
        tasks.push(path);
    }

    void run(int num_threads) {
        for (int i = 0; i < num_threads; i++) {
            threads.emplace_back([this]() {
                while (true) {
                    std::string path;
                    {
                        std::lock_guard<std::mutex> lock(mtx);
                        if (tasks.empty()) return;
                        path = tasks.front();
                        tasks.pop();
                    }
                    auto res = hash_file_mmap(path);
                    {
                        std::lock_guard<std::mutex> lock(res_mtx);
                        results.push_back(std::move(res));
                    }
                }
            });
        }
        for (auto& t : threads) t.join();
    }

    std::vector<FileHash>& get_results() { return results; }
};

// ── Commands ────────────────────────────────────────────

void cmd_hash(const std::string& path) {
    auto result = hash_file_mmap(path);
    if (result.error) {
        std::cerr << "  ❌ " << result.errmsg << ": " << path << std::endl;
        return;
    }
    std::cout << result.hash << "  " << path << std::endl;
}

void cmd_scan(const std::string& dir, int threads_n) {
    std::cout << "\n🗿  GOLEM — Memory-Mapped File Hasher" << std::endl;
    std::cout << "═══════════════════════════════════════" << std::endl;
    std::cout << "  Target:  " << dir << std::endl;
    std::cout << "  Threads: " << threads_n << std::endl;

    auto start = std::chrono::steady_clock::now();

    WorkerPool pool;
    size_t file_count = 0;

    for (auto& entry : fs::recursive_directory_iterator(dir,
            fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            pool.add_file(entry.path().string());
            file_count++;
        }
    }

    std::cout << "  Files:   " << file_count << std::endl;
    std::cout << "  ─────────────────────────────────────" << std::endl;

    pool.run(threads_n);

    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    auto& results = pool.get_results();
    std::sort(results.begin(), results.end(),
              [](const FileHash& a, const FileHash& b) { return a.path < b.path; });

    size_t total_bytes = 0;
    size_t errors = 0;

    for (auto& r : results) {
        if (r.error) {
            std::cerr << "  ⚠️  " << r.errmsg << ": " << r.path << std::endl;
            errors++;
        } else {
            std::cout << "  " << r.hash << "  " << r.path;
            if (r.size > 1048576)
                std::cout << "  (" << (r.size / 1048576) << " MB)";
            std::cout << std::endl;
            total_bytes += r.size;
        }
    }

    std::cout << "\n  ─────────────────────────────────────" << std::endl;
    std::cout << "  Hashed: " << (results.size() - errors) << " files, "
              << (total_bytes / 1048576) << " MB total" << std::endl;
    if (errors > 0)
        std::cout << "  Errors: " << errors << std::endl;
    std::cout << "  Time:   " << elapsed << "s (" << threads_n << " threads)" << std::endl;
    std::cout << std::endl;
}

void cmd_verify(const std::string& manifest) {
    std::cout << "\n🗿  GOLEM — Integrity Verification" << std::endl;
    std::cout << "═══════════════════════════════════════" << std::endl;

    std::ifstream in(manifest);
    if (!in.is_open()) {
        std::cerr << "  ❌ Cannot open: " << manifest << std::endl;
        return;
    }

    int ok = 0, changed = 0, missing = 0;
    std::string line;

    while (std::getline(in, line)) {
        // Skip empty lines and headers
        if (line.empty() || line[0] == '#' || line[0] == '=') continue;
        // Parse "hash  path" or "  hash  path"
        std::istringstream iss(line);
        std::string expected_hash, path;
        iss >> expected_hash >> path;
        if (expected_hash.size() != 64 || path.empty()) continue;

        auto result = hash_file_mmap(path);
        if (result.error) {
            std::cout << "  🔴 MISSING  " << path << std::endl;
            missing++;
        } else if (result.hash != expected_hash) {
            std::cout << "  🟡 CHANGED  " << path << std::endl;
            std::cout << "      was: " << expected_hash << std::endl;
            std::cout << "      now: " << result.hash << std::endl;
            changed++;
        } else {
            ok++;
        }
    }

    std::cout << "\n  ─────────────────────────────────────" << std::endl;
    std::cout << "  ✅ OK: " << ok << "  🟡 Changed: " << changed
              << "  🔴 Missing: " << missing << std::endl;
    std::cout << std::endl;
}

void print_help() {
    std::cout << R"(
🗿  nullsec-golem v)" << VERSION << R"( — Memory-Mapped File Hasher (C++)
   Part of the nullsec freakshow suite.

Usage:
  golem hash <file>                 SHA-256 hash a single file
  golem scan <dir> [-t threads]     Hash all files in directory
  golem verify <manifest>           Verify against saved hashes
  golem --help                      This help

Examples:
  golem hash /etc/passwd
  golem scan /etc -t 8
  golem scan /usr/bin > manifest.txt
  golem verify manifest.txt

)" << std::endl;
}

// ── main ────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) { print_help(); return 0; }

    std::string cmd = argv[1];

    if (cmd == "hash" && argc >= 3) {
        cmd_hash(argv[2]);
    } else if (cmd == "scan" && argc >= 3) {
        int threads = std::thread::hardware_concurrency();
        if (threads < 1) threads = 4;
        for (int i = 3; i < argc; i++) {
            if (std::string(argv[i]) == "-t" && i + 1 < argc) {
                threads = std::atoi(argv[i + 1]);
                i++;
            }
        }
        cmd_scan(argv[2], threads);
    } else if (cmd == "verify" && argc >= 3) {
        cmd_verify(argv[2]);
    } else if (cmd == "--help" || cmd == "-h") {
        print_help();
    } else {
        print_help();
    }
    return 0;
}
