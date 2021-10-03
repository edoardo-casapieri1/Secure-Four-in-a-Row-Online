
/*** GAME ***/
const unsigned int GAME_OVER = 101;
const unsigned int GAME_OVER_TIE = 102;
const int rows = 8;
const int columns = 11;
extern int field[rows][columns];
extern bool endGame;
extern int counterMoves;
extern int winner;

void initGame();
void printField();
bool win_row(int row, int token);
bool win_column(int column, int token);
bool win_diag_sx(int column, int row, int token);
bool win_diag_dx(int column, int row, int token);
bool move(int column, int token);

