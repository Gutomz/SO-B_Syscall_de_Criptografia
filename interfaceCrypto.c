#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>


int main()
{
        char cryptoWord[256];
	char decryptoResult[256];

	int fdCryptoFile;
	struct stat st;

	int opcao;

	size_t cryptoWordSize;

        do
        {
		system("clear");
                printf("Escolha o que deseja fazer:\n1-Cryptografar uma Palavra\n2-Descriptografar o arquivo\n3-Sair\n");
                scanf("%d", &opcao);

                switch (opcao)
                {
                case 1:
			fdCryptoFile = open("/home/guto/Desktop/cryptoFile.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 0666);
			if (fdCryptoFile == -1)
			{
					printf("Erro ao abrir o CryptoFile\n");
					break;
			}		
	
                        printf("Digite a frase a ser criptografada:\n");
			getchar();
                        scanf("%[^\n]", cryptoWord);
			cryptoWordSize = strlen(cryptoWord);
			cryptoWord[(int)cryptoWordSize] = '\0';


			printf("%s\n", cryptoWord);
                        //fazer syscall writeCrypto
			
			if(syscall(548, fdCryptoFile, cryptoWord, cryptoWordSize)){
				printf("Mensagem foi criptografada corretamente\n");
			}else{
				printf("Algo deu errado ...\n");
			}

			close(fdCryptoFile);
  			
			getchar();
                        break;

                case 2:
			getchar();
			fdCryptoFile = open("/home/guto/Desktop/cryptoFile.txt", O_RDONLY, 0666);
			if (fdCryptoFile == -1)
			{
				printf("Erro ao abrir o CryptoFile\n");
				getchar();

				break;
			}

			stat("/home/guto/Desktop/cryptoFile.txt", &st);
			cryptoWordSize = st.st_size;

			if(cryptoWordSize > 0){
			
		                printf("Frase criptografada:\n");

				if(syscall(549, fdCryptoFile, decryptoResult, cryptoWordSize) == -1){
					printf("Algo deu errado ...\n");
				}
	  			else printf("%s\n", decryptoResult);
			}else{
				printf("O arquivo está vazio!\n");
			}

			getchar();

			close(fdCryptoFile);
                        break;

                default:
                        break;
                }

        }while(opcao != 3);

        return 0;

}
