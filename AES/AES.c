#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
 
#define BYTE unsigned char
int _Nr = 0;        //設定Nr
int _Nk = 0;        //設定Nk
int _keyLen = 0;    //設定keyLen
// sbox尋找的表
BYTE AES_Sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};
// sboxInv尋找的表
BYTE AES_SboxInv[] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
// ShiftRow交換的順序
BYTE AES_ShiftRowsIndex[] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};

//在畫面上顯示出傳入的arr
void printBytes(BYTE arr[], int len) {
    int i;
    printf("\n");
    for (i=0; i<len; i++){
        if( i != 0 && i % 16 == 0) printf("\n");
        printf("%02X ", arr[i]);
    }
    printf("\n");
}
//AES_AddRoundKey的作法
void aes_AddRoundKey(BYTE *plainText, BYTE *key, int startBlock){
    //明文跟key做xor
    for(int i = 0; i < 16; i++){ 
        plainText[i] ^= key[startBlock + i]; 
    }
}
//AES_SubBytes的作法
void aes_SubBytes(BYTE *plainText){
    //依照明文對照AES_SBox
    for(int i = 0; i < 16; i++){
        plainText[i] = AES_Sbox[plainText[i]]; 
    }
}
//AES_SubBytesInv的作法
void aes_SubBytesInv(BYTE *cipherText){
    //將cipherText對照AES_SBoxInv
    for(int i = 0; i < 16; i++){
        cipherText[i] = AES_SboxInv[cipherText[i]]; 
    }
}
//AES_ShiftRows的作法
void aes_ShiftRows(BYTE *plainText){
    BYTE temp[16];
    for(int copy = 0; copy < 16; copy++){
        temp[copy] = plainText[copy];
    }
    //將每一個plainText依照row向左位移
    for(int i = 0; i < 16; i++){
        plainText[i] = temp[AES_ShiftRowsIndex[i]];
    }
}
//AES_ShiftRowsInv的作法
void aes_ShiftRowsInv(BYTE *plainText){
    BYTE temp[16];
    for(int copy = 0; copy < 16; copy++){
        temp[copy] = plainText[copy];
    }
    //將每一個plainText依照row向右位移
    for(int i = 0; i < 16; i++){
        plainText[AES_ShiftRowsIndex[i]] = temp[i];
    }
}
//AES_MixColumn中GF(2^n)計算的的方法
BYTE GF28Mode(BYTE a, BYTE b) {
	BYTE p = 0;
	BYTE counter;
	BYTE hi_bit_set;
	for(counter = 0; counter < 8; counter++) {
		if((b & 1) == 1) 
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if(hi_bit_set == 0x80) 
			a ^= 0x1b;		
		b >>= 1;
	}
	return p;
}
//AES_MixColumn的作法
void aes_MixColumn(BYTE *plainText){
    BYTE temp[16];
    for(int copy = 0; copy < 16; copy++){
        temp[copy] = plainText[copy];
    }
    for(int i = 0; i < 16; i+=4){
        plainText[i] = GF28Mode(0x02, temp[i]) ^ GF28Mode(0x03, temp[i+1]) ^ GF28Mode(0x01, temp[i+2]) ^ GF28Mode(0x01, temp[i+3]);
        plainText[i+1] = GF28Mode(0x01, temp[i]) ^ GF28Mode(0x02, temp[i+1]) ^ GF28Mode(0x03, temp[i+2]) ^ GF28Mode(0x01, temp[i+3]);
        plainText[i+2] = GF28Mode(0x01, temp[i]) ^ GF28Mode(0x01, temp[i+1]) ^ GF28Mode(0x02, temp[i+2]) ^ GF28Mode(0x03, temp[i+3]);
        plainText[i+3] = GF28Mode(0x03, temp[i]) ^ GF28Mode(0x01, temp[i+1]) ^ GF28Mode(0x01, temp[i+2]) ^ GF28Mode(0x02, temp[i+3]);
    }
}
//AES_MixColumnInv的作法
void aes_MixColumnInv(BYTE *plainText){
    BYTE temp[16];
    for(int copy = 0; copy < 16; copy++){
        temp[copy] = plainText[copy];
    }
    for(int i = 0; i < 16; i+=4){
        plainText[i] = GF28Mode(0x0E, temp[i]) ^ GF28Mode(0x0B, temp[i+1]) ^ GF28Mode(0x0D, temp[i+2]) ^ GF28Mode(0x09, temp[i+3]);
        plainText[i+1] = GF28Mode(0x09, temp[i]) ^ GF28Mode(0x0E, temp[i+1]) ^ GF28Mode(0x0B, temp[i+2]) ^ GF28Mode(0x0D, temp[i+3]);
        plainText[i+2] = GF28Mode(0x0D, temp[i]) ^ GF28Mode(0x09, temp[i+1]) ^ GF28Mode(0x0E, temp[i+2]) ^ GF28Mode(0x0B, temp[i+3]);
        plainText[i+3] = GF28Mode(0x0B, temp[i]) ^ GF28Mode(0x0D, temp[i+1]) ^ GF28Mode(0x09, temp[i+2]) ^ GF28Mode(0x0E, temp[i+3]);
    }
}
//AES的RoundKey擴展的方法（128bit、192bit、256bit）
void ase_key_expand(BYTE *key, int len){
    srand(time(NULL));
    BYTE keyOrigin[ _Nk * 4 ];
    printf("原始金鑰為：");
    printBytes(key, len);
    printf("全部的AddRoundKey為：");

    BYTE Rcon = 0x01;
    for(int j = _Nk * 4; j < 16 * (_Nr + 1); j+=4){
        if( j % (_Nk * 4) == 0 ){
            key[j] = key[ j - (_Nk * 4) ] ^ (AES_Sbox[key[j-3]] ^ Rcon) ;
            key[j+1] = key[ j - (_Nk * 4 - 1) ] ^ (AES_Sbox[key[j-2]] ^ 0x00) ;
            key[j+2] = key[ j - (_Nk * 4 - 2) ] ^ (AES_Sbox[key[j-1]] ^ 0x00) ;
            key[j+3] = key[ j - (_Nk * 4 - 3) ] ^ (AES_Sbox[key[j-4]] ^ 0x00) ;
            Rcon *= 2;
            if(Rcon == 0) Rcon ^= 0x11b;
        }else if( _Nk == 8 && j % 16 == 0){
            key[j] = key[ j - (_Nk * 4) ] ^ AES_Sbox[key[j-4]];
            key[j+1] = key[ j - (_Nk * 4 - 1) ] ^ AES_Sbox[key[j-3]];
            key[j+2] = key[ j - (_Nk * 4 - 2) ] ^ AES_Sbox[key[j-2]];
            key[j+3] = key[ j - (_Nk * 4 - 3) ] ^ AES_Sbox[key[j-1]];
        }else{
            key[j] = key[j-4] ^ key[ j - (_Nk * 4) ];
            key[j+1] = key[j-3] ^ key[ j - (_Nk * 4 - 1) ];
            key[j+2] = key[j-2] ^ key[ j - (_Nk * 4 - 2) ];
            key[j+3] = key[j-1] ^ key[ j - (_Nk * 4 - 3) ];
        }
    }
    printBytes(key, 16 * (_Nr + 1));
}
//基本的AES加密方法
void aes_Encrypt(BYTE *plainText, BYTE *key){
    int startBlock = 0;
    aes_AddRoundKey(plainText, key, startBlock);
    startBlock = 16;
    for(int i = 0; i < _Nr - 1 ; i++){
        aes_SubBytes(plainText);
        aes_ShiftRows(plainText);
        aes_MixColumn(plainText);
        aes_AddRoundKey(plainText, key, startBlock);
        startBlock += 16;
    }
    aes_SubBytes(plainText);
    aes_ShiftRows(plainText);
    aes_AddRoundKey(plainText, key, startBlock);
}
//基本的AES解密方法
void aes_Decrypt(BYTE *plainText, BYTE *key){
    int startBlock = 16 * _Nr;
    aes_AddRoundKey(plainText, key, startBlock);
    aes_ShiftRowsInv(plainText);
    aes_SubBytesInv(plainText);
    startBlock -= 16;
    for(int i = 0; i < _Nr - 1 ; i++){
        aes_AddRoundKey(plainText, key, startBlock);
        aes_MixColumnInv(plainText);
        aes_ShiftRowsInv(plainText);
        aes_SubBytesInv(plainText);
        startBlock -= 16;
    }
    aes_AddRoundKey(plainText, key, 0);
}
//依照secret key長度，初始化Nr、Nk、keyLen
void aes_init(int input){
    _Nr = (input + 4) * 2;
    _Nk = (input + 1) * 2;
    _keyLen = (input + 1) * 8;
}
//AES_ECB的加密解密流程
void AES_ECB(BYTE *plainText, BYTE *key, int plainTextLen){
    int count = 0;
    int cipherLen = ((plainTextLen/16) + 1) * 16;
    BYTE cipherBuffer[cipherLen];
    for(int cipherInt = 0;cipherInt<cipherLen;cipherInt++){
        cipherBuffer[cipherInt] = 0x00;
    }
    //AES_ECB加密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            temp[i] = plainText[ count * 16 + i];
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            cipherBuffer[ count * 16 + j ] = temp[j];
        }
        count += 1;
    }
    printf("待加密：");
    for(int plainTextCount = 0;plainTextCount < plainTextLen;plainTextCount++){
        printf("%c ",plainText[plainTextCount]);
    }
    printf("\n加密後：");
    printBytes(cipherBuffer, cipherLen);
    
    count = 0;
    BYTE plainTextBuffer[cipherLen];
    for(int plainTextInt = 0;plainTextInt<cipherLen;plainTextInt++){
        plainTextBuffer[plainTextInt] = 0x00;
    }
    //AES_ECB解密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            temp[i] = cipherBuffer[ count * 16 + i];
        }
        aes_Decrypt(temp, key);
        for(int j = 0;j<16;j++){
            plainTextBuffer[ count * 16 + j ] = temp[j];
        }
        count += 1;
        
    }
    printf("\n解密後：");
    printBytes(plainTextBuffer, cipherLen);
}
//AES_CBC的加密解密流程
void AES_CBC(BYTE *plainText, BYTE *key, int plainTextLen){
    int count = 0;
    int cipherLen = ((plainTextLen/16) + 1) * 16;
    BYTE cipherBuffer[cipherLen];
    char initVectorChar[16];
    BYTE initVector[16] = {0x00};
    BYTE initVectorTemp[16] = {0x00};

    printf("-------------------------\n");
    printf("Input the InitVector：");
    scanf("%s", initVectorChar);
    for(int i = 0; i < strlen(initVectorChar); i++){
        initVector[i] = initVectorChar[i];
        initVectorTemp[i] = initVectorChar[i];
    }
    for(int cipherInt = 0;cipherInt<cipherLen;cipherInt++){
        cipherBuffer[cipherInt] = 0x00;
    }
    //AES_CBC加密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            temp[i] = plainText[ count * 16 + i] ^ initVectorTemp[i];
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            initVectorTemp[j] = temp[j];
            cipherBuffer[ count * 16 + j ] = temp[j];
        }
        count += 1;
    }
    printf("待加密：");
    for(int plainTextCount = 0;plainTextCount < plainTextLen;plainTextCount++){
        printf("%c ",plainText[plainTextCount]);
    }
    printf("\n加密後：");
    printBytes(cipherBuffer, cipherLen);
    
    count = 0;
    BYTE plainTextBuffer[cipherLen];
    for(int i = 0; i < 16; i++){
        initVectorTemp[i] = initVector[i];
    }
    //AES_CBC解密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            temp[i] = cipherBuffer[ count * 16 + i];
        }
        aes_Decrypt(temp, key);
        for(int j = 0;j<16;j++){
            plainTextBuffer[ count * 16 + j ] = temp[j] ^ initVectorTemp[j];
            initVectorTemp[j] = cipherBuffer[ count * 16 + j];
        }
        count += 1;
        
    }
    printf("\n解密後：");
    printBytes(plainTextBuffer, cipherLen);
}
//AES_CFB的加密解密流程
void AES_CFB(BYTE *plainText, BYTE *key, int plainTextLen){
    int count = 0;
    int cipherLen = ((plainTextLen/16) + 1) * 16;
    BYTE temp[16] = {0x00};
    BYTE cipherBuffer[cipherLen];
    char initVectorChar[16];
    BYTE initVector[16] = {0x00};
    BYTE initVectorTemp[16] = {0x00};

    printf("-------------------------\n");
    printf("Input the InitVector：");
    scanf("%s", initVectorChar);
    for(int i = 0; i < strlen(initVectorChar); i++){
        initVector[i] = initVectorChar[i];
        initVectorTemp[i] = initVectorChar[i];
    }
    for(int cipherInt = 0;cipherInt<cipherLen;cipherInt++){
        cipherBuffer[cipherInt] = 0x00;
    }
    //AES_CFB加密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        for(int i = 0;i<16;i++){
            temp[i] = initVectorTemp[i];
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            cipherBuffer[ count * 16 + j ] = temp[j] ^ plainText[ count * 16 + j];
            initVectorTemp[j] = cipherBuffer[ count * 16 + j ];
        }
        count += 1;
    }
    printf("待加密：");
    for(int plainTextCount = 0;plainTextCount < plainTextLen;plainTextCount++){
        printf("%c ",plainText[plainTextCount]);
    }
    printf("\n加密後：");
    printBytes(cipherBuffer, cipherLen);
    
    count = 0;
    BYTE plainTextBuffer[cipherLen];
    for(int i = 0; i < 16; i++){
        initVectorTemp[i] = initVector[i];
    }
    //AES_CFB解密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        for(int i = 0;i<16;i++){
            temp[i] = initVectorTemp[i];
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            plainTextBuffer[ count * 16 + j ] = temp[j] ^ cipherBuffer[ count * 16 + j];
            initVectorTemp[j] = cipherBuffer[ count * 16 + j];
        }
        count += 1;
        
    }
    printf("\n解密後：");
    printBytes(plainTextBuffer, cipherLen);
}
//AES_OFB的加密解密流程
void AES_OFB(BYTE *plainText, BYTE *key, int plainTextLen){
    int count = 0;
    int cipherLen = ((plainTextLen/16) + 1) * 16;
    BYTE cipherBuffer[cipherLen];
    char initVectorChar[16];
    BYTE initVector[16] = {0x00};
    BYTE initVectorTemp[16] = {0x00};

    printf("-------------------------\n");
    printf("Input the InitVector：");
    scanf("%s", initVectorChar);
    for(int i = 0; i < strlen(initVectorChar); i++){
        initVector[i] = initVectorChar[i];
        initVectorTemp[i] = initVectorChar[i];
    }
    for(int cipherInt = 0;cipherInt<cipherLen;cipherInt++){
        cipherBuffer[cipherInt] = 0x00;
    }
    //AES_OFB加密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            temp[i] = initVectorTemp[i];
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            initVectorTemp[j] = temp[j];
            cipherBuffer[ count * 16 + j ] = temp[j] ^ plainText[ count * 16 + j];
        }
        count += 1;
    }
    printf("待加密：");
    for(int plainTextCount = 0;plainTextCount < plainTextLen;plainTextCount++){
        printf("%c ",plainText[plainTextCount]);
    }
    printf("\n加密後：");
    printBytes(cipherBuffer, cipherLen);
    
    count = 0;
    BYTE plainTextBuffer[cipherLen];
    for(int i = 0; i < 16; i++){
        initVectorTemp[i] = initVector[i];
    }
    //AES_OFB解密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            temp[i] = initVectorTemp[i];
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            initVectorTemp[j] = temp[j];
            plainTextBuffer[ count * 16 + j ] = cipherBuffer[ count * 16 + j] ^ temp[j];
        }
        count += 1;
    }
    printf("\n解密後：");
    printBytes(plainTextBuffer, cipherLen);
}
//AES_CTR的加密解密流程
void AES_CTR(BYTE *plainText, BYTE *key, int plainTextLen){
    int count = 0;
    int cipherLen = ((plainTextLen/16) + 1) * 16;
    BYTE cipherBuffer[cipherLen];
    char nonceChar[16];
    BYTE nonce[16] = {0x00};

    printf("-------------------------\n");
    printf("Input the Nonce：");
    scanf("%s", nonceChar);
    for(int i = 0; i < strlen(nonceChar); i++){
        nonce[i] = nonceChar[i];
    }
    for(int cipherInt = 0;cipherInt<cipherLen;cipherInt++){
        cipherBuffer[cipherInt] = 0x00;
    }
    //AES_OFB加密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            if(i ==15){
                temp[i] = nonce[i] + count;
            }else{
                temp[i] = nonce[i] ;
            }
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            cipherBuffer[ count * 16 + j ] = temp[j] ^ plainText[ count * 16 + j];
        }
        count += 1;
    }
    printf("待加密：");
    for(int plainTextCount = 0;plainTextCount < plainTextLen;plainTextCount++){
        printf("%c ",plainText[plainTextCount]);
    }
    printf("\n加密後：");
    printBytes(cipherBuffer, cipherLen);
    
    count = 0;
    BYTE plainTextBuffer[cipherLen];
    //AES_OFB解密迴圈
    while( count != ((plainTextLen / 16) + 1)){
        BYTE temp[16] = {0x00};
        for(int i = 0;i<16;i++){
            if(i ==15){
                temp[i] = nonce[i] + count;
            }else{
                temp[i] = nonce[i] ;
            }
        }
        aes_Encrypt(temp, key);
        for(int j = 0;j<16;j++){
            plainTextBuffer[ count * 16 + j ] = cipherBuffer[ count * 16 + j] ^ temp[j];
        }
        count += 1;
    }
    printf("\n解密後：");
    printBytes(plainTextBuffer, cipherLen);
}
//主程式進入點
int main(void){
    int keyLen;
    while(1){
        //顯示選擇key長度的Ｍenu
        printf("----Length Menu----------------\n");
        printf("1.) 128 bits\n");
        printf("2.) 192 bits\n");
        printf("3.) 256 bits\n");
        printf("4.) exit\n");
        printf("-------------------------\n");
        printf("Choice a secret key length to start algorithm,\n");
        printf("=> ");
        scanf("%d", &keyLen);
        if (keyLen == 4){
            printf("Process has been terminated.\n\n");
            exit(1);
        }else if(keyLen > 4){
            printf("輸入錯誤的資料\n");
            exit(1);
        }
        aes_init(keyLen);
        //輸入secret key
        printf("-------------------------\n");
        printf("Input the secret key : ");
        BYTE key[ 16 * (_Nr + 1) ];
        for(int keyCount = 0; keyCount < 16 * (_Nr + 1); keyCount++){
            key[keyCount] = 0x00;
        }
        char keyChar[100] = {0x00};
        scanf("%s", keyChar);

        for(int i = 0; i < (keyLen + 1) * 8; i++){
            key[i] = keyChar[i];
        }
        //顯示選擇AES的模式，並輸入欲加密的明文
        int AES_mode = 0;
        char plainTextChar[100];
        BYTE plainTextByte[100] = {0x00};
        printf("----Mode Menu----------------\n");
        printf("1.) AES-ECB \n");
        printf("2.) AES-CBC \n");
        printf("3.) AES-CFB \n");
        printf("4.) AES-OFB \n");
        printf("5.) AES-CTR \n");
        printf("-------------------------\n");
        printf("Choice a AES mode,\n");
        printf("=> ");
        scanf("%d", &AES_mode);
        printf("-------------------------\n");
        printf("Input the plainText,\n");
        printf("=> ");
        scanf("%s", plainTextChar);
        for(int i = 0; i < strlen(plainTextChar); i++){
            plainTextByte[i] = plainTextChar[i];
        }
        //執行所選擇的AES模式
        if(AES_mode == 1){
            ase_key_expand(key, _keyLen);
            AES_ECB(plainTextByte, key, strlen(plainTextChar));
        }else if(AES_mode == 2){
            ase_key_expand(key, _keyLen);
            AES_CBC(plainTextByte, key, strlen(plainTextChar));
        }else if(AES_mode == 3){
            ase_key_expand(key, _keyLen);
            AES_CFB(plainTextByte, key, strlen(plainTextChar));
        }else if(AES_mode == 4){
            ase_key_expand(key, _keyLen);
            AES_OFB(plainTextByte, key, strlen(plainTextChar));
        }else if(AES_mode == 5){
            ase_key_expand(key, _keyLen);
            AES_CTR(plainTextByte, key, strlen(plainTextChar));
        }else{
            printf("輸入錯誤的資料\n");
            exit(1);
        }
    }
    
    return 0;
}