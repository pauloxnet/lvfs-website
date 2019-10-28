rule IntelBiosGuard
{
    meta:
        license = "GPL-2.0+"
        description = "Contains Intel BIOS Guard"
        fail = false
        claim = "intel-bios-guard"

    strings:
        $signature = "_AMIPFAT"
        $updater = "AmiFlashUpd" wide
        $header = "__BGKH__"

    condition:
       $header or ($signature and not $updater)
}
