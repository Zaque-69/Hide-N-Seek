rule jpg_rule {
    strings : 
                $s0 = { FF D8 FF DB }
                $s1 = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
                $s2 = { FF D8 FF EE }
                $s3 = { FF D8 FF E1 87 90 45 78 69 66 00 00 }
    condition : any of them 
}