rule _0b1c49ec2d53c4af21a51a34d9aa91e76195ceb442480468685418ba8ece1ba6 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "14/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // bitcoin-core
        $b1 = { 62 69 74 63 6F 69 6E 2D 63 6F 72 65 }

        // /icons/bitcoin
        $b2 = { 2F 69 63 6F 6E 73 2F 62 69 74 63 6F 69 6E }
            
        //CWallet::GetDebit()
        $b3 = { 43 57 61 6C 6C 65 74 3A 3A 47 65 74 44 65 62 69 74 28 29 }

        // https://en.bitcoin.it/wiki/BIP_0022
        $b4 = { 68 74 74 70 73 3A 2F 2F 65 6E 2E 62 69 74 63 6F 69 6E 2E 69
            74 2F 77 69 6B 69 2F 42 49 50 5F 30 30 32 32 }
   
        // s.p.o.j.e.n.i.a.m
        $b5 = { 73 00 70 00 6F 00 6A 00 65 00 6E 00 69 00 61 00 6D }

        // p.r.e.n.d.n.a.s.t.a.v.e.n
        $b6 = { 70 00 72 00 65 00 64 00 6E 00 61 00 73 00 74 00 61 00 76 00 65 00 6E }

        // a.l.e.b.o t.e.s.t.o.v.a.c.i.a s.i.e.e
        $b7 = { 61 00 6C 00 65 00 62 00 6F 00 20 00 74 00 65 00 73 00 74 00 6F 00 76
            00 61 00 63 00 69 00 61 00 20 00 73 00 69 00 65 01 65 }

    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* ) 
        and filesize < 10000KB
}