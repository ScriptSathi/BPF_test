struct data_t
{
    int pid;
    int uid;
    char command[16];
    char message[12];
    char path[16];
    char argv[8][50];
};