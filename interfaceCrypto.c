#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int openFile(int operation){
	int fdCryptoFile;

	switch(operation){
		case 1:
		default:
			fdCryptoFile = open("/home/guto/Desktop/cryptoFile.txt", O_RDONLY, 0666);
		break;

		case 2:
			fdCryptoFile = open("/home/guto/Desktop/cryptoFile.txt", O_RDWR | O_CREAT | O_APPEND, 0666);
		break;
	}

	if (fdCryptoFile == -1)
	{
		printf("Erro ao abrir o arquivo\n");
		getchar();
		return -1;
	}

	return fdCryptoFile;
}


int main()
{
	struct stat st;

	int opcao, i, ret, status;
	int fileSize;
	int fdCryptoFile;
	int cryptoWordSize;
	char *msg;
	char *oldMsg;
	char c;

	do{
		do{
			system("clear");
			printf("Escolha o que deseja fazer:\n");
			printf("1 - Ler o arquivo (Criptografado)\n");
			printf("2 - Ler o arquivo (Descriptografado)\n");
			printf("3 - Escrever no arquivo\n");
			printf("4 - Apagar o arquivo\n");
			printf("0 - Sair\n");
			printf("Resposta: ");
			scanf("%d", &opcao);
		}while(opcao < 0 || opcao > 4);
		getchar();

		switch (opcao)
		{
			case 1:
				
				if((fdCryptoFile = openFile(1)) == -1) break;

				stat("/home/guto/Desktop/cryptoFile.txt", &st);
				fileSize = st.st_size;

				if(fileSize <= 0){
					printf("Arquivo vazio!\n");
					getchar();
					break;
				}

				msg = malloc(fileSize);

				ret = read(fdCryptoFile, msg, fileSize);

				if(ret == -1){
					printf("Não foi possível ler o arquivo!\n");
					if(msg) free(msg);
					getchar();
					break;
				}

				system("clear");
				for(i = 0; i < ret; i++) printf("%c", msg[i]);
				printf("\n\nPressione qualquer tecla para continuar ...");

				if(msg) free(msg);
				close(fdCryptoFile);
				getchar();

			break;

			case 2:
				
				if((fdCryptoFile = openFile(1)) == -1) break;

				stat("/home/guto/Desktop/cryptoFile.txt", &st);
				fileSize = st.st_size;

				if(fileSize <= 0){
					printf("Arquivo vazio!\n");
					getchar();
					break;
				}

				msg = malloc(fileSize);

				ret = syscall(549, fdCryptoFile, msg, fileSize);

				if(ret == -1){
					printf("Não foi possível ler o arquivo!\n");
					if(msg) free(msg);
					getchar();
					break;
				}

				system("clear");
				for(i = 0; i < ret; i++) {
					if(msg[i] != '\0')
						printf("%c", msg[i]);
				}
				printf("\n\nPressione qualquer tecla para continuar ...");

				if(msg) free(msg);
				close(fdCryptoFile);
				getchar();
			break;

			case 3:

				if((fdCryptoFile = openFile(2)) == -1) break;

				stat("/home/guto/Desktop/cryptoFile.txt", &st);
				fileSize = st.st_size;

				if(fileSize > 0){
					oldMsg = malloc(fileSize);
					ret = syscall(549, fdCryptoFile, oldMsg, fileSize);

					if(ret == -1){
						printf("Erro ao carregar o arquivo! Tente novamente mais tarde ...");
						if(oldMsg) free(oldMsg);
						getchar();
						break;
					}

				}

				msg = malloc(500);

				system("clear");
				printf("Digite a mensagem (MAX 500 CARACTERES):\n\n");

				if(oldMsg) 
					for(i = 0; i < ret; i++) 
						if(oldMsg[i] != '\0') printf("%c", oldMsg[i]);

				scanf("%[^\n]", msg);

				cryptoWordSize = strlen(msg);
				if(cryptoWordSize > 500) {
					cryptoWordSize = 500;
					__fpurge(stdin);
				}

				ret = syscall(548, fdCryptoFile, msg, cryptoWordSize);

				if(ret) printf("\nMensagem Criptografada corretamente!\n");
				else printf("\nAlgo deu errado. Tente novamente!\n");
				getchar();

				if(msg) free(msg);
				if(oldMsg) free(oldMsg);
				close(fdCryptoFile);
				getchar();

			break;

			case 4:
				status = remove("/home/guto/Desktop/cryptoFile.txt");

				system("clear");

				if(!status) printf("Arquivo apagado com sucesso!\n");
				else printf("Não foi possivel apagar o arquivo!\n");

				getchar();
			break;

			case 0:
			default:
				opcao = 0;
			break;

		}

		oldMsg = NULL;
		msg = NULL;

	}while(opcao != 0);

    return 0;

}
