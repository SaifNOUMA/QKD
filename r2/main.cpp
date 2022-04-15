#include "src/r2_process.cpp"

using namespace std;


int main() {
    OQS_STATUS  rc;

    rc = r2_process();
    if (rc == OQS_SUCCESS) {
        cout << "R2 process:     Success." << endl;
    } else {
        cout << "R2 process:     Failed." << endl;
        return -1;
    }


    return 0;
}
