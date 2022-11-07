#include <iostream>
#include <string>

using namespace std;


//задаём константы
int a = 44;
int b = 55;
int c = 66;

//задаём начальное значение
int z0 = 4;

int nextVal = z0;

//вычисляем следующее псевдослучайное число
int getNext() {
    nextVal = (a * nextVal + b) % c;
	return nextVal;
}

//шифруем(дешифруем) строку, посимвольно применяя XOR
string encrypt(string str) {
    nextVal = z0;
    for (int i = 0; i <= str.size(); i++) {
        str[i] ^= getNext();
    }
    return str;
}

int main()
{
    string str;
    cout << "Enter string\n";
    getline(cin, str);
    string enc_str = encrypt(str);
    cout << "Encoded string: " << enc_str << endl;
    string dec_str = encrypt(enc_str);
    cout << "Decoded string: " << dec_str << endl;
}
