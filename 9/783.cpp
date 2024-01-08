#include <iostream>
using namespace std;

int main()
{
    int i, j, n, a[256][256], s = 0;
    cin>>n;
    for ( i =1; i <= n; i++)
        for ( j = 1; j <=n; j++)
            cin>>a[i][j];

    for ( i = 1; i <= n; i++ ) s += a[i+1][i] + a[i][i+1];
    cout<<s;
    return 0;
}
