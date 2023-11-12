#include <iostream>
#include "client.h"

using std::cout, std::endl;

int main(){
    Client client;
    cout << "Starting client" << endl;

    client.start();

    return 0;
}