rule png_rule {
    strings : 
        $s0 = { 89 50 4E 47 }
    condition : any of them 
}