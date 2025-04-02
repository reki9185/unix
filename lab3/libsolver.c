#include <stdio.h>
#include <link.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "libgotoku.h"

#ifndef USE_SERVER
    #include "offset_server.h"
#else
    #include "offset_local.h"
#endif

#define GAMEPFX	"my_GOTOKU: "
#define MAX_MOVES 1200

static int SIZE = 9;

void* fHandle;
void* main_ptr;

int (*my_game_init)();
void* (*my_game_get_ptr)();
gotoku_t* (*my_game_load)();

int myBoard[9][9];

char *gop_fills[] = {
    "gop_fill_0", "gop_fill_1", "gop_fill_2", "gop_fill_3", 
    "gop_fill_4", "gop_fill_5", "gop_fill_6", "gop_fill_7", 
    "gop_fill_8", "gop_fill_9"
};

int is_valid_move(int row, int col, int num) {

    for (int i = 0; i < SIZE; i++) {
        if (myBoard[row][i] == num) {
            return 0;
        }
    }

    for (int i = 0; i < SIZE; i++) {
        if (myBoard[i][col] == num) {
            return 0;
        }
    }

    // Check the 3x3 subgrid
    int start_row = (row / 3) * 3;
    int start_col = (col / 3) * 3;
    for (int i = start_row; i < start_row + 3; i++) {
        for (int j = start_col; j < start_col + 3; j++) {
            if (myBoard[i][j] == num) {
                return 0;
            }
        }
    }

    return 1;
}

int solve(int start_row, int start_col) {

    int row, col;
    int found_empty = 0;

    for (row = start_row; row < SIZE; row++) {
        for (col = (row == start_row) ? start_col : 0; col < SIZE; col++) {
            if (myBoard[row][col] == 0) {
                found_empty = 1;
                break;
            }
        }
        if (found_empty) break;
    }

    if (!found_empty) return 1;

    for (int num = 1; num <= 9; num++) {
        if (is_valid_move(row, col, num)) {
            myBoard[row][col] = num;

            int next_row = row;
            int next_col = col + 1;
            if (next_col == SIZE) {
                next_row++;
                next_col = 0;
            }

            if (solve(row, col)) {
                return 1;
            }

            myBoard[row][col] = 0;
        }
    }

    return 0;
}

void execute(char *method, int cnt) {
    void (*gop)(void) = (void (*)(void))dlsym(fHandle, method);
    void *got = main_ptr - MAIN_OFFSET + got_offsets[cnt];

    uintptr_t page_start = (uintptr_t)got & ~(getpagesize() - 1);
    // Unlock the page for writing
    if (mprotect((void *)page_start, getpagesize(), PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect");
    }

    void **got_entry = (void **)got;
    *got_entry = (void *)gop;
}

void moves(gotoku_t* gt){
    int cnt = 0;
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (gt->board[i][j] != myBoard[i][j]) {
                int num = myBoard[i][j];
                execute(gop_fills[num], cnt++);

            }
            execute("gop_right", cnt++);
        }
        // go next row
        for (int i = 0; i < 9; i++) {
            execute("gop_left", cnt++);
        }
        execute("gop_down", cnt++);
    }
}

int game_init() {

    printf("UP113_GOT_PUZZLE_CHALLENGE\n");

    fHandle = dlopen("libgotoku.so", RTLD_LAZY);

    my_game_init = (int(*)())dlsym(fHandle, "game_init");
    my_game_get_ptr = (void*(*)())dlsym(fHandle, "game_get_ptr");

    main_ptr = my_game_get_ptr("main");
	printf("SOLVER: _main = %p\n", main_ptr);

    return my_game_init();

}

gotoku_t* game_load(const char *fn) {

    gotoku_t* gt = NULL;

    my_game_load = (gotoku_t*(*)())dlsym(fHandle, "game_load");

    char *error = dlerror();
    if (error) {
        printf("dlsym error: %s\n", error);
    }

    gt = my_game_load("gotoku.txt");

    for (int i = 0; i < 9; i++){
        for (int j = 0; j < 9; j++) {
            myBoard[i][j] = gt->board[i][j];
        }
    }

    solve(0, 0);
    moves(gt);
    return gt;

}