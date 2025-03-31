#include <stdio.h>
#include <link.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "libgotoku.h"

static int SIZE = 9;

gotoku_t *gt;
void* fHandle;

int (*my_game_init)();
void* (*my_game_get_ptr)();
gotoku_t* (*my_game_load)();

void* (*my_gop_show)();

void* (*my_gop_random)();

int is_valid_move(int row, int col, int num) {

    for (int i = 0; i < SIZE; i++) {
        if (gt->board[row][i] == num) {
            return 0;
        }
    }

    for (int i = 0; i < SIZE; i++) {
        if (gt->board[i][col] == num) {
            return 0;
        }
    }

    // Check the 3x3 subgrid
    int start_row = (row / 3) * 3;
    int start_col = (col / 3) * 3;
    for (int i = start_row; i < start_row + 3; i++) {
        for (int j = start_col; j < start_col + 3; j++) {
            if (gt->board[i][j] == num) {
                return 0;
            }
        }
    }

    return 1;
}

int solve() {

    int row, col;
    int found_empty = 0;

    for (row = 0; row < SIZE; row++) {
        for (col = 0; col < SIZE; col++) {
            if (gt -> board[row][col] == 0) {
                found_empty = 1;
                break;
            }
        }
        if (found_empty) break;
    }

    if (!found_empty) {
        return 1;
    }

    for (int num = 1; num <= 9; num++) {
        if (is_valid_move(row, col, num)) {
            gt -> board[row][col] = num;

            if (solve()) {
                return 1;
            }

            gt -> board[row][col] = 0;
        }
    }

    return 0;
}

int game_init() {

    printf("UP113_GOT_PUZZLE_CHALLENGE\n");

    fHandle = dlopen("libgotoku.so", RTLD_LAZY);

    my_game_init = (int(*)())dlsym(fHandle, "game_init");
    my_game_get_ptr = (void*(*)())dlsym(fHandle, "game_get_ptr");

    void* main_ptr = my_game_get_ptr("main");
	printf("SOLVER: _main = %p\n", main_ptr);

    my_gop_show = (void*(*)())dlsym(fHandle, "gop_show");

	// solve();

    return my_game_init();

}

gotoku_t* game_load(const char *fn){

    my_game_load = (gotoku_t*(*)())dlsym(fHandle, "game_load");

    gt = my_game_load("./gotoku.txt");

    // solve();

    return my_game_load();

}

void gop_random() {

    my_gop_random = (void*(*)())dlsym(fHandle, "gop_random");

    solve();

}