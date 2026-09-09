rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (bundled baseline rule for file-yara)"
        author = "ndr-file-yara"
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $b = "$H+H*"
    condition:
        $a and $b
}
