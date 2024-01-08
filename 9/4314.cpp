#include <iostream>

using namespace std;

int main()
{
    long long n, n2, cif, c = 0;
    cin>>n;
    n2 = n;
    while ( n > 0 ){
        cif = n % 10;
        n /= 10;
    }
    while ( n2 > 0 ){
        if ( n2 % 10 < cif ) c++;
        n2 /= 10;
    }
    cout<<c;
    return 0;
}
