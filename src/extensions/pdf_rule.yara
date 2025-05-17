rule pdf_rule {
    strings : 
        $s0 = { 25 50 44 46 2D }
    condition : any of them 
}