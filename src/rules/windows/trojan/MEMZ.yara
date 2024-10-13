rule MEMZ_positive {
    meta : 
        author = "Z4que - All rights reverved"
	   date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        $c1 = "ur computer has been trashed by the MEMZ trojan" ascii wide
        $c2 = "YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN" ascii wide
        $c3 = "Your computer won't boot up again" ascii wide
        $c4 = "best+way+to+kill+yourself" ascii wide

    condition : 
        ( $header at 0 ) and all of ( $c* )
}