#include <iostream>

using namespace std;

int main()
{
    int a[256][256], v[101], n, m, i, j, s = 0;
        
    cin>>n>>m;
    for (i = 1; i <= n; i++)
        for ( j = 1; j <= n; j++) 
            cin>>a[i][j];
    if ( m == 1)
        for ( i = 1; i <= n; i++){
            for ( j = 1; j <= n; j++){
                if ( i < j && i + j < n + 1) s += a[i][j];
            }
        }
    if ( m == 2)
        for ( i = 1; i <= n; i++){
            for ( j = 1; j <= n; j++){
                if ( i < j && i + j > n + 1) s += a[i][j];
            }
        }
    if ( m == 3)
        for ( i = 1; i <= n; i++){
            for ( j = 1; j <= n; j++){
                if ( i > j && i + j > n + 1) s += a[i][j];
            }
        }
    if ( m == 4)
        for ( i = 1; i <= n; i++){
            for ( j = 1; j <= n; j++){
                if ( i > j && i + j < n + 1) s += a[i][j];
            }
        }
    cout<<s;
    return 0;
}
