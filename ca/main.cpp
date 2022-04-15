#include "src/ca_kg.cpp"

using namespace std;


int main() {
    OQS_STATUS  rc;

    rc = key_gen();
    if (rc == OQS_SUCCESS) {
        cout << "Key generation: Success." << endl;
    } else {
        cout << "Key generation: Failure." << endl;
        return -1;
    }


    return 0;
}
