#include <capstone/capstone.h>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <map>
#include <assert.h>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <elf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <fcntl.h>

using namespace std;

uintptr_t entry, text_start, text_end, offset;

struct instruction {
    string opr, opnd;
    uint8_t bytes[16];
    size_t size;

};

struct breakpoint {
    uint64_t addr;
    // origin code of the addr
    unsigned char code;
};

vector<instruction> instructions;
map<int, breakpoint> breakpoints;

void disassemble(char* from, size_t size, uintptr_t address) {

    static csh cshandle = 0;

    // disassemble 5 instructions starting from rip
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) return;

    cs_option(cshandle, CS_OPT_SKIPDATA, CS_OPT_ON);

    // get the real entry
    // long off = ((long)from + text_start);
    
    cs_insn *insn;
    // int count = cs_disasm(cshandle, (uint8_t*)offset, size, address, 0, &insn);
    int count = cs_disasm(cshandle, (uint8_t*)from, size, address, 0, &insn);

    for (int i = 0; i < count; i++) {
        instruction in;
        in.size = insn[i].size;
        in.opr = insn[i].mnemonic;
        in.opnd = insn[i].op_str;
        memcpy(in.bytes, insn[i].bytes, insn[i].size);

        instructions.push_back(in);
    }

    cs_free(insn, count);
    cs_close(&cshandle);

}

class sdb{
public:

    void set_program(string name) {

        char *argv[] = {&name[0], nullptr};

        program = argv[0];

        pid = fork();
        // child process
        if (pid == 0) {
            // indicate that this process is to be traced by its parent
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            execvp(argv[0], argv);
            exit(0);

        } else if (pid < 0) {
            cerr << "fork error" << endl;
            waitpid(pid, NULL, 0);

        // parent process
        } else {
            int status;
            waitpid(pid, &status, 0);

            assert(WIFSTOPPED(status));

            // set option: kill the tracee if the tracer exit | syscall
            ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
            // ptrace(PTRACE_CONT, pid, NULL, NULL);

            get_text_section(program);
            get_entry();
            cout << "** program '" << program << "' loaded. entry point: 0x" << std::hex << entry_address << "." << endl;
            set_entry();

            // cout << std::hex << entry_address << endl;

            // do_assembly(regs.rip);
            // waitpid(pid, &status, 0);
            
        }
    }

    void start() {

        while(1) {
            shell();
        }
    }

private:

    void shell() {
        cout << "(sdb) ";

        string cmd;
        cin >> cmd;

        if (cmd == "exit" || cmd == "q") {
            exit(0);

        }

        // check if the program is empty
        if (cmd != "load" && program.empty()) {
            cout << "** please load a program first." << endl;
            cin.clear();
            cin.sync();

            return;
        }

        // commands
        if (cmd == "load") {
            if (!program.empty()) {
                cerr << "** a program is already loaded." << endl;
                return;

            } else {
                cin >> program;
                set_program(program);
            }

        } else if (cmd == "si") {
            do_si();

        } else if (cmd == "break" || cmd == "b") {
            uint64_t addr;
            cin >> std::hex >> addr;
            set_breakpoint(addr);

        } else if (cmd == "cont") {
            do_cont();

        } else if (cmd == "info") {
            string var;
            cin >> var;

            if (var == "reg") {
                do_info_reg();

            } else if (var == "break") {
                do_info_bp();

            }
            
        } else if (cmd == "breakrva") {
            uint64_t var;
            cin >> std::hex >> var;

            // cout << std::hex << offset << endl;

            uint64_t addr = text_start + (var - offset);

            set_breakpoint(addr);

        } else if (cmd == "delete") {
            int value;
            cin >> value;

            del_breakpoint(value);

        } else if (cmd == "patch") {
            string hex_addr, hex_string;
            cin >> hex_addr >> hex_string;

            do_patch(hex_addr, hex_string);

        } else if (cmd == "syscall") {
            do_syscall();

        } else {
            cerr << "** unknown command [" << cmd << "]" << endl; 
        }

    }

    void do_cont() {

        ptrace(PTRACE_CONT, pid, NULL, NULL);
        do_execute();
        after_cont = true;
        // do_assembly(regs.rip);
    }

    void do_assembly(uint64_t rip) {
        // read memory at rip
        unsigned char code[64] = {0};
        uint64_t ptr = rip;

        size_t offset = 0;

        while(offset < sizeof(code)) {
            // get a word from a memory address of the tracee
            long data  = ptrace(PTRACE_PEEKTEXT, pid, ptr, NULL);

            // check if there is breakpoint (replace int3 to origin code)
            for (int i = 0; i < 8 && offset < sizeof(code); i++) {
                uint64_t cur_addr = ptr + i;
                unsigned char byte = (data >> (8 * i)) & 0xff;

                if (breakpoint* bp = getBreakpoint(cur_addr)) {
                    byte = bp->code;
                }

                code[offset++] = byte;
            }

            ptr += 8;
        }

        instructions.clear();

        disassemble((char*)code, ptr - rip, rip);

        // print the disassembled instructions
        int count = min(5, (int)instructions.size());

        for (int i = 0; i < count; i++) {
            // const auto &in = instructions[i];
            print(&instructions[i], rip);
            rip += instructions[i].size;
        }

        if (count < 5) {
            cout << "** the address is out of the range of the executable region." << endl;
        }

    }

    void print(instruction *in, int64_t rip) {
        // address
        printf("      %lx: ", rip);

        // raw bytes
        for (size_t j = 0; j < in->size; ++j) {
            printf("%02x ", in->bytes[j]);
        }

        printf("%*s", int(32 - in->size * 3), "");
        printf("%s %s\n", in->opr.c_str(), in->opnd.c_str());
    }

    void do_si() {

        // if si() after cont() -> ignore
        if (after_cont) {
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            do_assembly(regs.rip);

            after_cont = false;
            return;
        }

        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        do_execute();

        // do_assembly(regs.rip);
        
    }

    // rdx, r12, r15, r10, rip, rdi, r8, r11, r14, eflags

    void do_info_reg() {
        // update regs info
        // ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        cout << std::hex << " $rax 0x" << setw(16) << setfill('0') << regs.rax << "\t\t$rbx 0x" << setw(16) << setfill('0') << regs.rbx << "\t\t$rcx 0x" << setw(16) << setfill('0') << regs.rcx << endl;
        cout << std::hex << " $rdx 0x" << setw(16) << setfill('0') << regs.rdx << "\t\t$rsi 0x" << setw(16) << setfill('0') << regs.rsi << "\t\t$rdi 0x" << setw(16) << setfill('0') << regs.rdi << endl;
        cout << std::hex << " $rbp 0x" << setw(16) << setfill('0') << regs.rbp << "\t\t$rsp 0x" << setw(16) << setfill('0') << regs.rsp << "\t\t$r8  0x" << setw(16) << setfill('0') << regs.r8  << endl;
        cout << std::hex << " $r9  0x" << setw(16) << setfill('0') << regs.r9  << "\t\t$r10 0x" << setw(16) << setfill('0') << regs.r10 << "\t\t$r11 0x" << setw(16) << setfill('0') << regs.r11 << endl;
        cout << std::hex << " $r12 0x" << setw(16) << setfill('0') << regs.r12 << "\t\t$r13 0x" << setw(16) << setfill('0') << regs.r13 << "\t\t$r14 0x" << setw(16) << setfill('0') << regs.r14 << endl;
        cout << std::hex << " $r15 0x" << setw(16) << setfill('0') << regs.r15 << "\t\t$rip 0x" << setw(16) << setfill('0') << regs.rip << "\t\t$eflags 0x" << setw(16) << setfill('0') << regs.eflags << endl;

        cout << "$rbp - $rsp: 0x" << std::hex << regs.rbp - regs.rsp << endl;

    }

    void do_info_bp() {

        if (breakpoints.empty()) {
            cout << "** no breakpoints." << endl;
            return;
        }

        cout << "Num\t" << "Address\t" << endl;
        for (int i = 0; i < breakpoints.size(); i++) {
            cout << i << "\t0x" << std::hex << breakpoints[i].addr << "\t" << endl; 
        } 
    }

    void do_execute() {

        int status;
        waitpid(pid, &status, 0);
        long code;

        if (is_terminated(status)) {
            cerr << "** the target program terminated." << endl;
            program.clear();
            return;
        }

        // check if the last instruction is a breakpoint
       
        // update regs info
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        uint64_t pre_addr = regs.rip - 1;

        breakpoint *bp = getBreakpoint(pre_addr);

        if (bp) {

            do_breakpoint(bp);
            return;

        }

        // check if the current instruction is a bp
        code = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
        bp = getBreakpoint(regs.rip);

        if ((uint8_t)code == 0xcc && bp) {

            do_breakpoint(bp);
            return;

        }

        // if syscall
        uint64_t addr = regs.rip - 0x02;
        code = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
        
        if (WSTOPSIG(status) & 0x80 && is_syscall) {

            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            
            if (regs.rax == -ENOSYS) {
                cout << "** enter a syscall(" << std::dec << regs.orig_rax << ") at 0x" << std::hex << addr << "." << endl;

            } else {
                cout << "** leave a syscall(" << std::dec << regs.orig_rax << ") = " << regs.rax << " at 0x" << std::hex << addr << "." << endl;
            }

            do_assembly(addr);

            is_syscall = false;
            return;
        }

        do_assembly(regs.rip);

    }

    void do_breakpoint(breakpoint *bp) {
        
        long code;
        if (bp->addr != entry_address) cout << "** hit a breakpoint at 0x" << std::hex << bp->addr << "." << endl;

        // regs.rip = bp->addr;

        // cout << regs.rip << endl;
        regs.rip = bp->addr;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        // restore original byte
        code = ptrace(PTRACE_PEEKTEXT, pid, (void*)bp->addr, NULL);
        ptrace(PTRACE_POKETEXT, pid, (void*)bp->addr, (code & 0xffffffffffffff00) | bp->code);

        // step the original instruction
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        waitpid(pid, NULL, 0);

        do_assembly(bp->addr);

        // reload breakpoint (so it still a bp next round)
        code = ptrace(PTRACE_PEEKTEXT, pid, (void*)bp->addr, NULL);
        ptrace(PTRACE_POKETEXT, pid, (void*)bp->addr, (code & 0xffffffffffffff00) | 0xcc);
    }

    void do_patch(string &addr_str, string &str) {
        uint64_t addr = stoull(addr_str, nullptr, 16);
        size_t len = str.length();

        // convert hex string to byte vector
        vector<uint8_t> bytes;
        for (size_t i = 0; i < len; i += 2) {
            string byte_str = str.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(stoul(byte_str, nullptr, 16));
            bytes.push_back(byte);
        }

        // validate address range
        if (addr < text_start || (addr + bytes.size()) > text_end) {
            cout << "** the target address is not valid." << endl;
            return;
        }

        // patch memory byte by byte
        for (size_t i = 0; i < bytes.size(); i++) {
            uint64_t cur_addr = addr + i;
            uint64_t word = ptrace(PTRACE_PEEKTEXT, pid, cur_addr & ~0x7, nullptr);
            uint8_t offset = cur_addr & 0x7;

            // patch the byte inside the word
            uint64_t masked_word = (word & ~(0xffULL << (offset * 8))) | ((uint64_t)bytes[i] << (offset * 8));
            ptrace(PTRACE_POKETEXT, pid, cur_addr & ~0x7, masked_word);

            // TODO: update the breakpoints

        }
        
        cout << "** patch memory at address 0x" << std::hex << addr << "." << std::endl;

    }

    void do_syscall() {
        is_syscall = true;

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        do_execute();
    }

    void set_breakpoint(uint64_t addr) {

        breakpoint bp;
        bp.addr = addr;

        if (find(addr) != -1) {
            cerr << "** there is already a breakpoint at 0x" << std::hex << addr << endl;
            return;
        }

        if (addr < text_start || addr >= text_end) {
            cout << "** the target address is not valid.\n";
            return;
        }

        // writes INT3(0xcc) to the target code
        long data = ptrace(PTRACE_PEEKTEXT, pid, bp.addr, NULL);
        // save the origin code in bp.code
        bp.code = data & 0xff;

        uint64_t int3 = (data & 0xffffffffffffff00) | 0xcc;
        ptrace(PTRACE_POKETEXT, pid, bp.addr, int3);
        
        cout << "** set a breakpoint at 0x" << addr << "." << endl;

        int bp_id = 0;
        while (breakpoints.count(bp_id)) bp_id++;

        breakpoints[bp_id] = bp;

    }

    // for setting bp at entry address
    void set_breakpoint(uint64_t addr, uint64_t entry) {

        breakpoint bp;
        bp.addr = addr;

        // writes INT3(0xcc) to the target code
        long data = ptrace(PTRACE_PEEKTEXT, pid, bp.addr, NULL);
        // save the origin code in bp.code
        bp.code = data & 0xff;

        uint64_t int3 = (data & 0xffffffffffffff00) | 0xcc;
        ptrace(PTRACE_POKETEXT, pid, bp.addr, int3);

        breakpoints[0] = bp;

    }

    void del_breakpoint(int id) {

        // check if the bp exsist
        if (breakpoints.find(id) == breakpoints.end()) {
            cerr << "breakpoint " << id << " does not exist." << endl;
            return;
        }

        if (breakpoints[id].addr != entry_address) {
            cout << "** delete breakpoint " << id << "." << endl;
        }

        breakpoints.erase(id);
    }

    int find(int64_t addr) {
        for (int i = 0; i < breakpoints.size(); i++) {
            if (addr == breakpoints[i].addr) {
                return i;
            }
        }

        return -1;
    }


    bool is_terminated(int status) {
        return WIFEXITED(status);
    }

    breakpoint* getBreakpoint(uint64_t addr) {

        for (auto &it : breakpoints) {
            if (it.second.addr == addr) {
                return &it.second;
            }
        }

        return nullptr;

    }

    // get the .text section range using ELF
    void get_text_section(string& path) {

        ifstream file(path, std::ios::binary);
        std::vector<Elf64_Shdr> section_headers;

        file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));

        // read section header
        file.seekg(ehdr.e_shoff);
        section_headers.resize(ehdr.e_shnum);
        file.read(reinterpret_cast<char*>(section_headers.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));

        // read section header string table
        shstrtab = section_headers[ehdr.e_shstrndx];
        std::vector<char> shstrtab_data(shstrtab.sh_size);
        file.seekg(shstrtab.sh_offset);
        file.read(shstrtab_data.data(), shstrtab.sh_size);

        // find .text section
        for (const auto& sh : section_headers) {
            const char* name = &shstrtab_data[sh.sh_name];
            if (std::strcmp(name, ".text") == 0) {
                text_start = sh.sh_addr;
                text_end = sh.sh_addr + sh.sh_size;
                offset = sh.sh_offset;
                break;
            }
        }

        entry = ehdr.e_entry;

        // cout << "Entry: 0x" << std::hex << entry << endl; 

        // cout << "Text section: 0x" << std::hex << text_start
        //      << " - 0x" << text_end << std::dec << endl;
    }

    void get_entry() {

        // if the program is PIE 
        if (ehdr.e_type == ET_DYN) {
            entry_address = entry + get_base_address();
            text_end += get_base_address();

        } else {
            entry_address = entry;
        }

    }

    void set_entry() {

        set_breakpoint(entry_address, entry_address);
        do_cont();
        del_breakpoint(0);

    }

    unsigned long get_base_address() {

        char proc_maps_path[256];
        snprintf(proc_maps_path, sizeof(proc_maps_path), "/proc/%d/maps", pid);

        FILE* file = fopen(proc_maps_path, "r");

        unsigned long base_address = 0;

        // read the first entry from /proc/pid/maps
        unsigned long start_address, end_address;
        char exe[5];
        char path[256];
        int ret = fscanf(file, "%lx-%lx %4s %*s %*s %*s %255s\n", &start_address, &end_address, exe, path);

        // cout << std::hex << start_address << endl;
        // cout << std::hex << exe << endl;
        // cout << std::hex << path << endl;

        base_address = start_address;

        fclose(file);

        return base_address;
    }

    string program;
    pid_t pid;
    struct user_regs_struct regs;
    bool is_syscall = false;
    bool after_cont = false;
    Elf64_Ehdr ehdr;
    Elf64_Shdr shstrtab;
    uint64_t entry_address;

};

int main(int argc, char* argv[]) {

    sdb debugger;

    if (argc != 1) {
        debugger.set_program(argv[1]);
    }

    debugger.start();

    return 0;
}