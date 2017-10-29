#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/aes.h>



void decifraComChave(unsigned char *key, unsigned char *cifrado){

    AES_KEY chave;

    unsigned char *blocos[92]; //#Linhas

    unsigned char blocoDecifrar[16];
    unsigned char bloco_claro[16];
    unsigned char bloco_claro_print[17];

    for(int linha=0; linha<92; linha++){
        blocos[linha] = &cifrado[linha*16];
    }

    AES_set_decrypt_key(key, 128, &chave);

    for(int blocoAtual = 0; blocoAtual<92; blocoAtual++){
        memcpy(blocoDecifrar, blocos[blocoAtual], 16);
        AES_ecb_encrypt(blocoDecifrar, bloco_claro, &chave, AES_DECRYPT);
        memcpy(bloco_claro_print, bloco_claro, 16);
        bloco_claro_print[16] = (unsigned char) "\0";
        printf("%s\n", bloco_claro_print);
    }
}

int main(){

    /*******************INICIALIZACAO************************/

    mpz_t gInv, g, n, X, Y, inversoTeste, K, x, KeyTest, AESProdKey, Div256;
    char nRep[] = "340282366920938463463374607431768211297";
    char gRep[] = "339661812359158752487805590648382727301";
    char XRep[] = "217752919763112980997405005489123510636"; // x * g mod n
    char YRep[] = "298233162195654143916628869899206392532"; // y * g mod n
    int AESKey[16];

    mpz_init_set_str(g, gRep, 10);
    mpz_init_set_str(n, nRep, 10);
    mpz_init_set_str(X, XRep, 10);
    mpz_init_set_str(Y, YRep, 10);
    mpz_init(gInv);
    mpz_init(inversoTeste);
    mpz_init(K);
    mpz_init(x);
    mpz_init(KeyTest);
    mpz_init(AESProdKey);
    mpz_init_set_str(Div256, "256", 10);

    /***************************************************/

    mpz_invert(gInv, g, n); //g-1

    mpz_mul(K, X, Y);       // K = X*Y*g-1 mod n
    mpz_mul(K, K, gInv);
    mpz_mod(K, K, n);

    /**************************************************/

    for(int i=0; i<16; i++){
        mpz_mod(AESProdKey, K, Div256);
        AESKey[i] = (int) mpz_get_ui(AESProdKey);
        mpz_fdiv_q(K, K, Div256);
        //printf("%d\n", AESKey[i]);
    }

    FILE *fp = fopen("/Users/Airton/Dev/Seguranca/DHellman/arquivo1.txt", "r+"); //Caminho absoluto

    char hexDigit[3];
    int Arquivo[1472];
    char *endP;
    for(int i=0; i<92; i++){
        for(int j=0; j<17; j++) {
            if(j<16) {
                fread(hexDigit, sizeof(char), 2 * sizeof(char), fp);
                hexDigit[2] = 0;
                Arquivo[16 * i + j] = (int) strtol(hexDigit, &endP, 16);
            }
            else{
                fread(hexDigit, sizeof(char), 1* sizeof(char), fp);
            }
        }
    }

    unsigned char AESKEYTODEC[16];
    unsigned char TextoCripto[1472];
    for(int i=0; i<16; i++){
        AESKEYTODEC[i] = (unsigned char) AESKey[i];
    }
    for(int i=0; i<1472; i++){
        TextoCripto[i] = (unsigned char) Arquivo[i];
    }

    decifraComChave(AESKEYTODEC, TextoCripto);

    return 0;
}