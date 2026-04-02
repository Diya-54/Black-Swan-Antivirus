rule MALW_Mirai_Satori_ELF {
    strings:
        $a = "Mirai_Satori"
    condition:
        $a
}
