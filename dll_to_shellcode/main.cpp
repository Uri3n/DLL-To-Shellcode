#include "main.hpp"

std::optional<std::vector<char>>
read_from_disk(const std::string& file_name)
{
    std::ifstream input(file_name, std::ios::binary);
    std::vector<char> out;

    //------------------------------------------------------//

    auto _ = defer([&]() {
        if (input.is_open()) {
            input.close();
        }
    });

    if (!input.is_open()) {
        std::cerr << "[!] ERROR, Failed to open input file: " << file_name << std::endl;
        return std::nullopt;
    }

    input.seekg(0, std::ios::end);
    const std::streamsize file_size = input.tellg();
    input.seekg(0, std::ios::beg);

    out.resize(file_size);
    if (!input.read(out.data(), file_size)) {
        std::cerr << "[!] ERROR, Failed to read file contents: " << file_name << std::endl;
        return std::nullopt;
    }

    std::cout << "[+] Read from disk: " << file_name << std::endl;
    return out;
}

void concatenate(const std::vector<char>& stub, std::vector<char>& input_file)
{
    std::vector<unsigned char> get_image_base = {
        0xE8, 0x00, 0x00, 0x00, 0x00,              // call 0
        0x59,                                      // pop RCX
        0x48, 0x81, 0xC1, 0x00, 0x00, 0x00, 0x00   // add RCX, <offset>
    };

    *reinterpret_cast<uint32_t*>(&get_image_base[9]) = static_cast<uint32_t>(stub.size() + 8);

    input_file.insert(input_file.begin(), stub.begin(), stub.end());
    input_file.insert(input_file.begin(), get_image_base.begin(), get_image_base.end());
}

bool write_output(const std::vector<char>& buff, const std::string& of_name)
{
    std::ofstream of(of_name, std::ios::binary);
    if (!of.is_open()) {
        std::cerr << "[!] ERROR, Could not open output file." << std::endl;
        return false;
    }

    of.write(buff.data(), buff.size());
    of.close();

    std::cout << "[+] Successfully saved shellcode to: " << of_name << std::endl;
    return true;
}

bool test_run(const std::vector<char>& shellcode) {
#ifdef WINDOWS
    HANDLE hthread         = nullptr;
    void* pages            = nullptr;
    uint32_t old_protect   = 0;
    uint32_t thread_tid    = 0;
    uint32_t exit_code     = 0;

    pages = VirtualAlloc(
      nullptr,
      shellcode.size(),
      MEM_RESERVE | MEM_COMMIT,
      PAGE_READWRITE
    );

    if (pages == nullptr) {
        std::cerr << "[!] ERROR, VirtualAlloc failed with: " << GetLastError() << std::endl;
        return false;
    }

    memcpy(pages, shellcode.data(), shellcode.size());
    if (!VirtualProtect(
      pages,
      shellcode.size(),
      PAGE_EXECUTE_READ,
      reinterpret_cast<PDWORD>(&old_protect)
    )) {
        std::cerr << "[!] ERROR, VirtualProtect failed with: " << GetLastError() << std::endl;
    }

    std::cout << "[+] Shellcode at: 0x" << pages << std::endl;
    std::cout << "[+] Protection: R/X" << std::endl;
    std::cout << "[+] Creating thread...\n"
              << std::endl;

    hthread = CreateThread(
      nullptr,
      0,
      static_cast<LPTHREAD_START_ROUTINE>(pages),
      nullptr,
      0,
      reinterpret_cast<LPDWORD>(&thread_tid)
    );

    if (hthread == nullptr) {
        std::cerr << "[!] ERROR, CreateThread failed with: " << GetLastError() << std::endl;
        return false;
    }

    WaitForSingleObject(hthread, INFINITE);
    GetExitCodeThread(hthread, reinterpret_cast<LPDWORD>(&exit_code));

    std::cout << "\n[+] Thread with TID " << thread_tid << " has exited with code " << exit_code << std::endl;
    return true;

#else
    std::cerr << "[!] ERROR, Cannot run the outputted shellcode on non-Windows machines." << std::endl;
    return false;
#endif // #ifdef WINDOWS
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cout << " ~ DLL To Shellcode Converter ~ " << std::endl;
        std::cout << "  Usage: [INPUT DLL FILE] [OUTPUT FILE] [TESTRUN]" << std::endl;
        std::cout << "  Examples: dll_to_shellcode input.dll out.bin testrun" << std::endl;
        std::cout << "            dll_to_shellcode input.dll out.bin" << std::endl;
        std::cout << "\n  Note: the \"testrun\" argument is optional, and only works on Windows." << std::endl;
        return EXIT_FAILURE;
    }

    if (!std::filesystem::exists(argv[1]) || std::filesystem::path(argv[1]).extension().string() != ".dll") {
        std::cerr << "[!] ERROR, Input file does not exist, or is not a DLL." << std::endl;
        return EXIT_FAILURE;
    }

    std::string stub_path;
    if (std::filesystem::exists("stub.bin")) {
        stub_path = "stub.bin";
    } else if (std::filesystem::exists("stub/stub.bin")) {
        stub_path = "stub/stub.bin";
    } else {
        std::cerr << "[!] ERROR, Failed to locate stub.bin. "
                     "Please place the loader stub in the same directory as this executable.\n";
        return EXIT_FAILURE;
    }

    auto stub = read_from_disk(stub_path);
    auto input_file = read_from_disk(argv[1]);

    if (!stub || !input_file) {
        return EXIT_FAILURE;
    }

    concatenate(stub.value(), input_file.value());
    if (!write_output(*input_file, argv[2])) {
        return EXIT_FAILURE;
    }

    if (argc > 3 && std::string(argv[3]) == "testrun") {
        test_run(*input_file);
    }

    return EXIT_SUCCESS;
}
