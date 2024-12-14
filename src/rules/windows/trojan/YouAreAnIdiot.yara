rule YouAreAnIdiot_positive {
    meta : 
        author = "Z4que - All rights reverved"
        date = "14/12/2024"

    strings : 
        $header = { 4D 5A }

        // YouAreAnIdiot.exe
        $a1 = { 59 6F 75 41 72 65 41 6E 49 64 69 6F 74 2E 65 78 65 } 

        // MyTemplate.10.0.0.0
        $a2 = { 4D 79 54 65 6D 70 6C 61 74 65 08 31 30 2E 30 2E 30 2E 30 }

        // C:\Users\KenYue\documents\visual studio 2010
        $a3 = { 43 3A 5C 55 73 65 72 73 5C 4B 65 6E 59 75 65 5C 64 6F 63 75 6D 65 6E 74 73 5C 76 69 73 75 61 6C 20 73 74 75 64 69 6F 20 32 30 31 30 }

        // \Projects\YouAreAnIdiot\YouAreAnIdiot\obj\x86\Debug\YouAreAnIdiot.pdb
        $a4 = { 5C 50 72 6F 6A 65 63 74 73 5C 59 6F 75 41 72 65 41 6E 49 64 69 6F 74 5C 59 6F 75 41 72 65 41 6E 49 64 69 6F 74 5C 6F 62 6A 5C 78 38 36 5C 44 65 62 75 67 5C 59 6F 75 41 72 65 41 6E 49 64 69 6F 74 2E 70 64 62 }

        // I think you are an idiot
        $a5 = { 49 00 20 00 74 00 68 00 69 00 6E 00 6B 00 20 00 79 00 6F 00 75 00 20 00 61 00 72 00 65 00 20 00 61 00 6E 00 20 00 69 00 64 00 69 00 6F 00 74 }

        condition : 
            ( $header at 0 ) 
            and all of ( $a* )
}