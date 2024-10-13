rule RainbowIsKawaii_positive {
    meta : 
        author = "Z4que - All rights reverved"
	    date = "23/02/2024"

    strings : 
        $header = { 4D 5A }

        $c1 = "C:/Users/boris/documents/visual studio 2017/Projects/CookieClicker_Hack2017/CookieClicker_Hack2017/obj/Debug/CookieClicker_Hack2017.pdb" ascii wide
        //"Label4 STUPID? Button1 Yes yes !"
        $c2 = { 4C 00 61 00 62 00 65 00 6C 00 34 00 00 0F 53 00 54 00 55 00
                50 00 49 00 44 00 3F 00 00 0F 42 00 75 00 74 00 74 00 6F 00
                6E 00 31 00 00 11 59 00 65 00 73 00 20 00 79 00 65 00 73 00
                21 }
        //"Button2 Heck no"
        $c3 = { 42 00 75 00 74 00 74 00 6F 00 6E 00 32 00 00 11 48 00 65 00
                63 00 6B 00 20 00 6E 00 6F }

    condition : 
        ( $header at 0 ) 
        and any of ( $c* )
}