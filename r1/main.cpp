#include <iostream>
#include "src/r1_process.cpp"


using namespace std;


int main() {
    OQS_STATUS  rc;


    rc = r1_process();
    if (rc == OQS_SUCCESS) {
        cout << "R1 process:     Success." << endl;
    } else {
        cout << "R1 process:     Failed." << endl;
        return -1;
    }


    return 0;
}
