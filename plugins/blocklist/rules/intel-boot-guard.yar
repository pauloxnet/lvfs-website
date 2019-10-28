rule IntelBootGuard
{
    meta:
        license = "GPL-2.0+"
        description = "Contains Intel Boot Guard"
        fail = false
        claim = "intel-boot-guard"

    strings:
        $boot_policy_manifest_header = "__ACBP__"
        $ibb_element = "__IBBS__"

    condition:
       all of them
}
