#include <iostream>
#include <fstream>
#include <string.h>

#define ROUNDS 32

using namespace std;

//задаём константы и начальное значение для генерации ключа
//используя линейно-конгруэтный генератор
uint64_t a = 0x1fdfeaa314912340ULL;
uint64_t b = 0x0912492357b9c0f1ULL;
uint64_t c = 0x54124923dee1c0f1ULL;

uint64_t z0 = 0x897f98c9b797a97ULL;

uint64_t nextVal = z0;

uint64_t getNextKey() {
    nextVal = (a * nextVal + b) % c;
    return nextVal;
}

//шифрование
static inline void speck_round(uint64_t& x, uint64_t& y, const uint64_t& k)
{
    x = (x >> 8) | (x << (8 * sizeof(x) - 8)); // циклический сдвиг вправо на 8
    x += y;
    x ^= k;
    y = (y << 3) | (y >> (8 * sizeof(y) - 3)); // циклический сдвиг влево на 3
    y ^= x;
}

//шифрование
static inline void speck_back(uint64_t& x, uint64_t& y, const uint64_t& k)
{
    y ^= x;
    y = (y >> 3) | (y << (8 * sizeof(y) - 3)); // циклический сдвиг вправо на 3
    x ^= k;
    x -= y;
    x = (x << 8) | (x >> (8 * sizeof(x) - 8)); // циклический сдвиг влево на 8
}

//вычисляем ключ для каждого раунда
void speck_setup(uint64_t key_schedule[ROUNDS])
{
    uint64_t key1 = getNextKey();
    uint64_t key2 = getNextKey();
    key_schedule[0] = key2;
    for (unsigned i = 0; i < ROUNDS - 1; i++) {
        speck_round(key1, key2, i);
        key_schedule[i + 1] = key2;
    }
}

//шифруем блок, разбитый на 2 части
void speck_encrypt(const uint64_t plaintext[2]
    , const uint64_t key_schedule[ROUNDS]
    , uint64_t ciphertext[2])
{
    ciphertext[0] = plaintext[0];
    ciphertext[1] = plaintext[1];
    for (unsigned i = 0; i < ROUNDS; i++) {
        speck_round(ciphertext[1], ciphertext[0], key_schedule[i]);
    }
}

//дешифруем блок, разбитый на 2 части
void speck_decrypt(const uint64_t ciphertext[2]
    , const uint64_t key_schedule[ROUNDS]
    , uint64_t decrypted[2])
{
    decrypted[0] = ciphertext[0];
    decrypted[1] = ciphertext[1];
    for (unsigned i = ROUNDS; i > 0; i--) {
        speck_back(decrypted[1], decrypted[0], key_schedule[i - 1]);
    }
}

//считываем одну часть блока из файла
void read_block(ifstream& file, uint64_t& block) {
    char buf;
    for (size_t i = 0; i < 8; i++)
    {
	    file.get(buf);
        block = block << 8 | (unsigned char)buf;
    }
}

//перевод числа в строку
string uint_to_string(uint64_t val) {
    char buf[8];
    for (size_t i = 0; i < 8; i++)
    {
        buf[i] = ((val >> (8 * (7 - i))) & 255);
    }
    return string(buf, 8);
}

//шифрование файла
void encript(ifstream& input, ofstream& output) {
    //вычисляем длину файла
    long file_lenght = 0;
    char c;
    while (input.get(c))
    {
        file_lenght++;
    }
    input.clear();
    input.seekg(0);

    nextVal = z0;
    uint64_t block[2] = { 0, 0 };
    uint64_t ciphertext[2];
    uint64_t key_schedule[ROUNDS];

    //поблочно шифруем и выводим в файля
    for (int i = 0; i <= file_lenght - 16; i += 16)
    {
        speck_setup(key_schedule);
        read_block(input, block[0]);
        read_block(input, block[1]);
        speck_encrypt(block, key_schedule, ciphertext);
        output << uint_to_string(ciphertext[0]) << uint_to_string(ciphertext[1]);
    }

    //дополняем размер текста до размера блока
    char buf;
    block[0] = 0;
    block[1] = 0;
    speck_setup(key_schedule);
    for (int i = 0; i < 8; i++)
    {
        if (i < file_lenght % 16)
        {
            input.read(&buf, 1);
        }
        else if (i == file_lenght % 16)
        {
            buf = 128;
        }
        else
        {
            buf = 0;
        }
         block[0] = block[0] << 8 | (unsigned char)buf;
    }
    for (int i = 0; i < 8; i++)
    {
        if (i < file_lenght % 16 - 8)
        {
            input.read(&buf, 1);
        }
        else if (i == file_lenght % 16 - 8)
        {
            buf = 128;
        }
        else
        {
            buf = 0;
        }
        block[1] = block[1] << 8 | (unsigned char)buf;
    }
    speck_encrypt(block, key_schedule, ciphertext);
    output << uint_to_string(ciphertext[0]) << uint_to_string(ciphertext[1]);
}

//дешифрование файла
void decript(ifstream& input, ofstream& output) {
    //вычисляем длину файла
    long file_lenght = 0;
    char c;
    while (input.get(c))
    {
        file_lenght++;
    }
    input.clear();
    input.seekg(0);
    uint64_t block[2] = { 0, 0 };
    nextVal = z0;
    uint64_t decrypted[2];
    uint64_t key_schedule[ROUNDS];

    //поблочно дешифруем и выводим в файля
    for (int i = 0; i < file_lenght - 16; i += 16)
    {
        speck_setup(key_schedule);
        read_block(input, block[0]);
        read_block(input, block[1]);
        speck_decrypt(block, key_schedule, decrypted);
        output << uint_to_string(decrypted[0]) << uint_to_string(decrypted[1]);
    }
    //дешифруем последний блок
    speck_setup(key_schedule);
    read_block(input, block[0]);
    read_block(input, block[1]);
    speck_decrypt(block, key_schedule, decrypted);
    string str2 = uint_to_string(decrypted[1]);
    string str1 = uint_to_string(decrypted[0]);

    //убираем символы, которыми дополняли текст
    for (int i = str2.length(); i >= 0, i--;)
    {
        if (str2[i] == 0)
        {
            str2 = str2.substr(0, str2.length() - 1);
        }
        if ((unsigned char)str2[i] == 128)
        {
            str2 = str2.substr(0, str2.length() - 1);
            break;
        }
    }
    if (str1.length() == 0)
    {
        for (int i = str1.length(); i >= 0, i--;)
        {
            if (str1[i] == 0)
            {
                str1 = str1.substr(0, str1.length() - 1);
            }
            if ((unsigned char)str1[i] == 128)
            {
                str1 = str1.substr(0, str1.length() - 1);
                break;
            }
        }
    }
    output << str1 << str2;
}

int main() {
    ifstream plainfile("file.txt", ios::binary);
    ofstream cipherfile("cipherfile.txt", ios::binary);
    encript(plainfile, cipherfile);
    plainfile.close();
    cipherfile.close();

    ifstream cipherfile1("cipherfile.txt", ios::binary);
    ofstream decryptedfile("decryptedfile.txt", ios::binary);
    decript(cipherfile1, decryptedfile);
    cipherfile1.close();
    decryptedfile.close();
    return 0;
}
