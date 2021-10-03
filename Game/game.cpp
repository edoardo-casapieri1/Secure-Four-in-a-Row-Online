#include <iostream>
#include <climits>
#include "game.h"

using namespace std;

int field[rows][columns];
bool endGame;
int counterMoves;
int winner = -1;

void initGame() {
    //for (int k = 0; k < rows; k++)
    //    field[k] = (int *) malloc(columns * sizeof(int *));

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < columns; j++) {
            if (j == 0 || j == 10)
                field[i][j] = -2; //-2 => bordi colonne
            else
                field[i][j] = -1; //-1 => spazio libero
            field[6][j] = -3; // -3 => Bordo righe
        }
    }

    for (int z = 2; z < columns - 2; z++)
        field[7][z] = -4;

    field[6][0] = -1;
    field[6][10] = -1;
    field[7][0] = -1;
    field[7][10] = -1;

    endGame = false;
    counterMoves = 0;
}

void printField() {

    int counter = 1;
    cout << "\n\n";
    for (int i = 0; i < rows; i++) {
        cout << "\t\t";
        for (int j = 0; j < columns; j++) {
            switch (field[i][j]) {
                case -1:
                    cout << " ";
                    break;
                case 0:
                    cout << "o";
                    break;
                case 1:
                    cout << "x";
                    break;
                case -2:
                    cout << "|";
                    break;
                case -3:
                    cout << "-";
                    break;
                case -4:
                    cout << counter++;
                    break;
            }
        }
        cout << endl;
    }
    cout << "\n\n";

}

bool win_row(int row, int token) {

    bool win = false;
    int counter = 1;
    for (int k = 2; k < columns - 2; k++) {
        if (k + 1 != columns - 2 && counter < 4) {
            if (field[row][k] == token) {
                if (field[row][k] == field[row][k + 1]) {
                    counter++;
                    if (counter == 4) {
                        win = true;
                        break;
                    }
                } else {
                    counter = 0;
                }
            }
        }
    }

    return win;

}

bool win_column(int column, int token) {

    bool win = false;
    int counter = 1;
    for (int k = 0; k < rows - 2; k++) {
        if (k + 1 != rows - 2 && counter < 4) {
            if (field[k][column] == token) {
                if (field[k][column] == field[k + 1][column]) {
                    counter++;
                    if (counter == 4) {
                        win = true;
                        break;
                    }
                } else {
                    counter = 0;
                }
            }
        }
    }

    return win;

}

bool win_diag_sx(int column, int row, int token) {

    bool win = false;
    int counter = 1;
    int tmp_column = column;
    int tmp_row = row;

    while (tmp_column - 1 >= 2 && tmp_row + 1 < 6) {
        //muovo verso sinistra
        if (tmp_column - 1 != 1 && tmp_row + 1 != rows - 2 && counter < 4) {
            if (field[tmp_row][tmp_column] == token) {
                if (field[tmp_row][tmp_column] == field[tmp_row + 1][tmp_column - 1]) {
                    counter++;
                    if (counter == 4) {
                        win = true;
                        break;
                    }
                } else {
                    counter = 0;
                }
            }
        }
        tmp_column = tmp_column - 1;
        tmp_row = tmp_row + 1;

    }

    if (!win) {
        tmp_column = column;
        tmp_row = row;
        while (tmp_column + 1 < 9 && tmp_row - 1 >= 0) {
            //muovo verso sinistra
            if (tmp_column + 1 != columns - 2 && tmp_row - 1 >= 0 && counter < 4) {
                if (field[tmp_row][tmp_column] == token) {
                    if (field[tmp_row][tmp_column] == field[tmp_row - 1][tmp_column + 1]) {
                        counter++;
                        if (counter == 4) {
                            win = true;
                            break;
                        }
                    }
                } else {
                    counter = 0;
                }
            }
            tmp_column = tmp_column + 1;
            tmp_row = tmp_row - 1;
        }
    }

    return win;

}

bool win_diag_dx(int column, int row, int token) {

    bool win = false;
    int counter = 1;
    int tmp_column = column;
    int tmp_row = row;
    while (tmp_column + 1 < 9 && tmp_row + 1 < 6) {
        //muovo verso destra
        if (tmp_column + 1 != columns - 2 && tmp_row + 1 != rows - 2 && counter < 4) {
            if (field[tmp_row][tmp_column] == token) {
                if (field[tmp_row][tmp_column] == field[tmp_row + 1][tmp_column + 1]) {
                    counter++;
                    if (counter == 4) {
                        win = true;
                        break;
                    }
                } else {
                    counter = 0;
                }
            }
        }
        tmp_column = tmp_column + 1;
        tmp_row = tmp_row + 1;
    }

    if (!win) {
        tmp_column = column;
        tmp_row = row;
        while (tmp_column - 1 >= 2 && tmp_row - 1 >= 0) {
            //muovo verso sinistra
            if (tmp_column - 1 != 1 && tmp_row - 1 >= 0 && counter < 4) {
                if (field[tmp_row][tmp_column] == token) {
                    if (field[tmp_row][tmp_column] == field[tmp_row - 1][tmp_column - 1]) {
                        counter++;
                        if (counter == 4) {
                            win = true;
                            break;
                        }
                    }
                } else {
                    counter = 0;
                }
            }
            tmp_column = tmp_column - 1;
            tmp_row = tmp_row - 1;
        }
    }

    return win;

}

bool move(int column, int token) {

    bool outcome = false;

    if (column + 1 > 1 && column + 1 < 9) {
        int i = 5;

        while (i >= 0) {
            if (field[i][column + 1] == -1) {
                outcome = true;
                counterMoves++;
                break;
            }
            i--;
        }

        if (outcome) {
            field[i][column + 1] = token;
            printField();

            if (win_row(i, token) || win_column(column + 1, token) || win_diag_dx(column + 1, i, token) ||
                win_diag_sx(column + 1, i, token)) {
                winner = token;
                endGame = true;
            }
        } else {
            cout << "Full column: can't add more pieces!" << endl;
            printField();
        }
    } else {
        cout << "Move not allowed!" << endl;
    }

    return outcome;

}
