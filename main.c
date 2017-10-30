#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/aes.h>



void decifraComChave(unsigned char *key, unsigned char *cifrado){

    //FILE *fp = fopen("/Users/Airton/Desktop/Decifrado1.txt", "w+");

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

void testDesafio2(mpz_t Key){


    mpz_t n, g, BobPublicKey, AlicePublicKey, BobSecretKey, exp2, exp3, exp5, exp7, tolBob, BobPublicKeyTest;
    char nRep[] = "340282366920938463463374607431768211297";
    char gRep[] = "2";
    char BobRep[] = "53433919510811966366616401819103159032";
    char AliceRep[] = "40362037268068745080703064746809964248";

    mpz_init_set_str(n, nRep, 10);
    mpz_init_set_str(g, gRep, 10);
    mpz_init_set_str(BobPublicKey, BobRep, 10);
    mpz_init_set_str(AlicePublicKey, AliceRep, 10);
    mpz_init(BobSecretKey);
    mpz_init(exp2);
    mpz_init(exp3);
    mpz_init(exp5);
    mpz_init(exp7);
    mpz_init(tolBob);
    mpz_init(BobPublicKeyTest);


    mpz_ui_pow_ui(tolBob, 10, 50);

    //Bob usa gerador de randomicos fraco
    // Y(BOB) = g^y mod n => y = 2^x*3^y*5^w*7^z
    // y tem menos que 50 digitos

    for(unsigned long int x=1; x<=166; x++){
        for(unsigned long int y=1; y<=104; y++){
            for(unsigned long int w=1; w<=71; w++){
                for(unsigned long int z=1; z<=59; z++){
                    mpz_ui_pow_ui(exp2, 2, x);
                    mpz_ui_pow_ui(exp3, 3, y);
                    mpz_ui_pow_ui(exp5, 5, w);
                    mpz_ui_pow_ui(exp7, 7, z);
                    mpz_mul(BobSecretKey, exp2, exp3);
                    mpz_mul(BobSecretKey, BobSecretKey, exp5);
                    mpz_mul(BobSecretKey, BobSecretKey, exp7);
                    if(mpz_cmp(BobSecretKey, tolBob)>0){    //if o y gerado é maior que 10^49
                        //printf("%d\n", z);
                        break;
                    }
                    else{
                        mpz_powm(BobPublicKeyTest, g, BobSecretKey, n);
                        //printf("%s\n", mpz_get_str(NULL, 10, BobPublicKeyTest));
                        if(mpz_cmp(BobPublicKey, BobPublicKeyTest) == 0){
                            printf("***************  ACHOU!!!!  ******************\n");
                            printf("y = %s\n", mpz_get_str(NULL, 10, BobSecretKey));
                            printf("Seeds: x = %d, y = %d, w = %d, z = %d\n", x, y, w, z);
                            printf("*************************************************\n");
                            x = 167;
                            y = 105;
                            w = 73;
                            z = 60;
                            break;
                        }

                    }
                }
            }
        }
    }
    mpz_set(Key, BobSecretKey);

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

    mpz_t BobSecretKey;
    mpz_init(BobSecretKey);

    testDesafio2(BobSecretKey);
    //printf("%s\n", mpz_get_str(NULL, 10, BobSecretKey));




    return 0;
}