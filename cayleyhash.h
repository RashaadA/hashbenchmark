#include <string>
#include <iostream>

using namespace std;

string hashString(const string& input);
void cayleyHash(const uint8_t* data, size_t len, uint8_t* out);