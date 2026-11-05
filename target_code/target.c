#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 5

struct User {
    char username[32];
    char password[32];
};

struct User users[MAX_USERS] = {
    {"admin", "admin123"},
    {"user", "pass"},
    {"guest", "guest"}
};

// -----------------------------
// Buffer Overflow (gets)
// -----------------------------
void vulnerable_input() {
    char buffer[64];


    printf("Enter your name: ");
    gets(buffer);  

    printf("Hello, %s\n", buffer);
}

// -----------------------------
// Format String Vulnerability
// -----------------------------
void format_string() {
    char input[128];

    printf("Enter format string: ");
    fgets(input, sizeof(input), stdin);

    printf(input);  // ❌ format string vulnerability
}

// -----------------------------
// Authentication (weak + overflow)
// -----------------------------
void login() {
    char username[32];
    char password[32];

    printf("Username: ");
    scanf("%s", username);  // ❌ no bounds checking

    printf("Password: ");
    scanf("%s", password);  // ❌ no bounds checking

    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(username, users[i].username) == 0 &&
            strcmp(password, users[i].password) == 0) {
            printf("Login success!\n");
            return;
        }
    }

    printf("Login failed\n");
}

// -----------------------------
// Command Injection
// -----------------------------
void run_command() {
    char cmd[128];

    printf("Enter command: ");
    scanf("%s", cmd);

    char full_cmd[256];
    sprintf(full_cmd, "ls %s", cmd);  // ❌ injection

    system(full_cmd);
}

// -----------------------------
// File Read (Path Traversal)
// -----------------------------
void read_file() {
    char filename[128];

    printf("Enter filename: ");
    scanf("%s", filename);

    FILE *f = fopen(filename, "r");  // ❌ no validation

    if (!f) {
        printf("Cannot open file\n");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }

    fclose(f);
}

// -----------------------------
// Unsafe Memory Handling
// -----------------------------
void memory_issue() {
    char *ptr = malloc(10);

    strcpy(ptr, "This string is too long for buffer");  // ❌ overflow

    printf("%s\n", ptr);

    free(ptr);

    // ❌ Use-after-free
    printf("After free: %s\n", ptr);
}

// -----------------------------
// Menu
// -----------------------------
void menu() {
    int choice;

    while (1) {
        printf("\n--- Vulnerable C App ---\n");
        printf("1. Input\n");
        printf("2. Format String\n");
        printf("3. Login\n");
        printf("4. Run Command\n");
        printf("5. Read File\n");
        printf("6. Memory Test\n");
        printf("0. Exit\n");
        printf("Choice: ");

        scanf("%d", &choice);
        getchar(); // consume newline

        switch (choice) {
            case 1:
                vulnerable_input();
                break;
            case 2:
                format_string();
                break;
            case 3:
                login();
                break;
            case 4:
                run_command();
                break;
            case 5:
                read_file();
                break;
            case 6:
                memory_issue();
                break;
            case 0:
                exit(0);
            default:
                printf("Invalid\n");
        }
    }
}

// -----------------------------
int main() {
    menu();
    return 0;
}
