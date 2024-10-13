rule HBMlocker_positive {
    meta : 
        author = "Z4que - All rights reverved"
	   date = "7/03/2024"

    strings : 
        $header = { 4D 5A }
  
        //HKEY_CUR.NTm..._USER\SOFTWA\MicZs\.{..t\Windows\CurIntVtsion -> change Win Registry
        $c1 = { 48 4B 45 59 5F 43 55 52 0F 4E 54 6D FB F2 FF 5F 55
                53 45 52 5C 53 4F 46 54 57 41 5C 4D 69 63 5A 73 5C
                7F 7B FB FF 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72
                49 6E 74 56 74 73 69 6F 6E }
        
        //I.N%userprofi.%\2503326..@.475
        $c2 = { 49 00 4E 25 75 73 65 72 70 72 6F 66 69 18 25 5C 32
                35 30 33 33 32 36 1E B0 40 F6 34 37 35 }
    condition : 
     
        ( $header at 0 ) and any of ( $c* ) 
}
