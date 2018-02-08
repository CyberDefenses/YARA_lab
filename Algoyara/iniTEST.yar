rule chm_file
{
    strings:
         $magic = { 49 54 53 46 03 00 00 00  60 00 00 00 01 00 00 00 }
    condition:
         $magic
}

rule excel_file
{
    strings:
         $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
         $workbook = "Workbook" wide nocase
         $msexcel = "Microsoft Excel" nocase
    condition:
         all of them
}


rule word_file
{
    strings:
         $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
         $worddoc = "WordDocument" wide
         $msworddoc = "MSWordDoc" nocase
    condition:
         $rootentry and ($worddoc or $msworddoc)
}

rule powerpoint_file
{
    strings:
         $pptdoc = "PowerPoint Document" wide nocase
         $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
         all of them
}

rule pdf_file
{
    strings:
         $a = "%PDF-"
    condition:
         $a at 0
}

rule pe_file
{
    condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule zip_file
{
    strings:
         $magic = { 50 4b 03 04 }
         $magic2 = { 50 4b 05 06 }
         $magic3 = { 50 4b 07 08 }
    condition:
         ($magic at 0) or ($magic2 at 0) or ($magic3 at 0)
}