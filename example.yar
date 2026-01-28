import "pe"
import "math"

private rule DEMO1
{
  meta:
    desc = "Demo1 rule. Hex alternatives, wildcards, not, jumps, string modifiers"
  strings:
    $h1 = { 90 ~F? [6] ?? ( 4F?1 82 | A0 CE~03) [2-5]DE}
    $s2 = "line1\nline2\t\"quote\"" xor(0x01-0xff) ascii private
  condition:
    #h1 in (0..100) >= 1 and
    ($s2 at pe.entry_point) or (any of ($s2, $h1) in (0..512))
}

rule DEMO2 : trojan loader
{
  meta:
    desc = "Demo2 showcasing condition features, references Demo1 rule"
    num1 = 34
    num2 = 009436
    num3 = 000
  strings:
    $http  = "http://" nocase
    $sig   = { 6A ?? 68 }
    $magic   = { 4D 5A }
  condition:
    uint16(0) == 0x5A4D and pe.is_pe and math.entropy(0, filesize) > 6.5 and
    (1 of ($http, $sig) or any of ($http, $sig) in (0..filesize\2)) and
    #sig in (0..filesize) >= 1 and $sig in (100..2000) and $magic at 0 and
    for any i in (0..#sig - 1) : (@sig[i] < filesize) and
    for any sec in pe.sections : (sec.virtual_size > 1000 and
    (sec.characteristics & 0x20000000) != 0) and DEMO1
}