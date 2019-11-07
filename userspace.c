#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
int main()
{
         long int amma = syscall(550); //550 representa o Código para o comando hello.c
         printf("System call sys_hello returned %ld\n", amma);
         return 0;
}