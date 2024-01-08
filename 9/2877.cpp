#include <iostream>

using namespace std;

int main()
{
    int n, m, i, j, a[256][256], v[256], aux;
    cin>>n;
    for ( i = 1; i <= n; i++)
        for ( j = 1; j <= n; j++){
            cin>>a[i][j]; 
        } 
        
    //cout << endl;      
    
    for ( i = 1; i <= n; i++){
        for ( j = 1; j <= n; j++){
            for ( int k = j; k <=n; k++){
                if ( a[i][j] > a[i][k]){
                    aux = a[i][j];
                    a[i][j] = a[i][k];
                    a[i][k] = aux;
                }
            }
        }
    }
    
    for ( i = 1; i <= n; i++){
        for ( j = 1; j <= n; j++){
            for ( int k = i; k <=n; k++){
                if ( a[i][j] > a[k][j]){
                    aux = a[i][j];
                    a[i][j] = a[k][j];
                    a[k][j] = aux;
                }
            }
        }
    }

    
    for ( i = 1; i <= n; i++ ){
        for ( j = 1; j <= n; j ++ ){
            cout <<a[i][j] << " ";
        }
        cout << endl;
    }
    
    /*
    
    for(i = 1; i <= 4; i++ ){
        for (j = i; j <= 4 ; j++){
            if (v[i] > v[j]){
            aux = v[i];
            v[i] = v[j];
            v[j] = aux;
            }
        }
    }
        
    */

    return 0;
}
