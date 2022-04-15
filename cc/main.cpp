#include <oqs/oqs.h>
#include "src/cc_process.cpp"

using namespace std;


int main() {
    OQS_STATUS  rc;

    rc = cc_process();
    if (rc == OQS_SUCCESS) {
        cout << "CC process:     Success." << endl;
    } else {
        cout << "CC process:     Failed." << endl;
        return -1;
    }


    return 0;
}
