#include <iostream>

using namespace std;

int main()
{
    int n, m, i, j, ok=0,mij,y,p,u;
    int v[100001];
    
    cin>>n;
    for(i=1; i<=n; i++){
        cin>>v[i];
    }
    cin>>m;
    for(j=1; j<=m; j++){
      cin>>y;
        p=1;u=n;ok=0;
        while (p<=u && ok==0)
        {mij=(p+u)/2;
         if (v[mij]==y) ok=1;
        else if (y<v[mij]) u=mij-1;
        else p=mij+1;
        }
       cout<<ok<<" ";
     }

    return 0;
}
