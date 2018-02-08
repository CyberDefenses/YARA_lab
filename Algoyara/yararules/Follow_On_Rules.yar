rule nonPE_embedded_exe
{
   strings:
       $a = "DOS mode" nocase
       $b = { 44 4F 53 20 6D 6F 64 65 }
   condition:
   $a or $b
}

rule office_fin4_dev
{
   meta:
       description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
       author = "Fireeye Labs"
       version = "1.0"
       source = "https://github.com/fireeye/iocs/blob/master/FIN4/MACROCHECK.yara"
   strings:
       $PARAMpword = "pword=" ascii wide
       $PARAMmsg = "msg=" ascii wide
       $PARAMuname = "uname=" ascii
       $userform = "UserForm" ascii wide
       $userloginform = "UserLoginForm" ascii wide
       $invalid = "Invalid username or password" ascii wide
       $up1 = "uploadPOST" ascii wide
       $up2 = "postUpload" ascii wide

   condition:
       all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}

rule OPSled {
strings:
 $a = {32 32 32 32 32 32}
condition:
 $a }
 

rule Derusbi_XOR_4byte_Key {
	meta:
		description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
		author = "Florian Roth"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
   strings:
      /* Op Code */
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }
      /*
      test    ecx, ecx
      jz      short loc_590170
      xor     [esi], eax
      add     [esi], ebx
      add     esi, 4
      dec     ecx
      jmp     short loc_590162
      */
   condition:
      $s1
}

rule Derusbi_DeepPanda
{
meta:
   author = "ThreatConnect Intelligence Research Team"
   reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"
strings:
   $D = "Dom4!nUserP4ss" wide ascii
condition:
   $D
}

rule Derusbi_Gen
{
meta:
   author = "ThreatConnect Intelligence Research Team"
strings:
   $2 = "273ce6-b29f-90d618c0" wide ascii
   $A = "Ace123dx" fullword wide ascii
   $A1 = "Ace123dxl!" fullword wide ascii
   $A2 = "Ace123dx!@#x" fullword wide ascii
   $C = "/Catelog/login1.asp" wide ascii
   $DF = "~DFTMP$$$$$.1" wide ascii
   $G = "GET /Query.asp?loginid=" wide ascii
   $L = "LoadConfigFromReg failded" wide ascii
   $L1 = "LoadConfigFromBuildin success" wide ascii
   $ph = "/photoe/photo.asp HTTP" wide ascii
   $PO = "POST /photos/photo.asp" wide ascii
   $PC = "PCC_IDENT" wide ascii
condition:
   any of them
}

rule Codoso_PlugX_3 {
   meta:
       description = "Detects Codoso APT PlugX Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "74e1e83ac69e45a3bee78ac2fac00f9e897f281ea75ed179737e9b6fe39971e3"
   strings:
       $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
       $s2 = "mcs.exe" fullword ascii
       $s3 = "McAltLib.dll" fullword ascii
       $s4 = "WinRAR self-extracting archive" fullword wide
   condition:
       uint16(0) == 0x5a4d and filesize < 1200KB and all of them
}
rule Codoso_PlugX_2 {
   meta:
       description = "Detects Codoso APT PlugX Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "b9510e4484fa7e3034228337768176fce822162ad819539c6ca3631deac043eb"
   strings:
       $s1 = "%TEMP%\\HID" fullword wide
       $s2 = "%s\\hid.dll" fullword wide
       $s3 = "%s\\SOUNDMAN.exe" fullword wide
       $s4 = "\"%s\\SOUNDMAN.exe\" %d %d" fullword wide
       $s5 = "%s\\HID.dllx" fullword wide
   condition:
       ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them ) or all of them
}
rule Codoso_CustomTCP_4 {
   meta:
       description = "Detects Codoso APT CustomTCP Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash1 = "ea67d76e9d2e9ce3a8e5f80ff9be8f17b2cd5b1212153fdf36833497d9c060c0"
       hash2 = "130abb54112dd47284fdb169ff276f61f2b69d80ac0a9eac52200506f147b5f8"
       hash3 = "3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa"
       hash4 = "02cf5c244aebaca6195f45029c1e37b22495609be7bdfcfcd79b0c91eac44a13"
   strings:
       $x1 = "varus_service_x86.dll" fullword ascii

       $s1 = "/s %s /p %d /st %d /rt %d" fullword ascii
       $s2 = "net start %%1" fullword ascii
       $s3 = "ping 127.1 > nul" fullword ascii
       $s4 = "McInitMISPAlertEx" fullword ascii
       $s5 = "sc start %%1" fullword ascii
       $s6 = "net stop %%1" fullword ascii
       $s7 = "WorkerRun" fullword ascii
   condition:
       ( uint16(0) == 0x5a4d and filesize < 400KB and 5 of them ) or
       ( $x1 and 2 of ($s*) )
}
rule Codoso_CustomTCP_3 {
   meta:
       description = "Detects Codoso APT CustomTCP Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"
   strings:
       $s1 = "DnsApi.dll" fullword ascii
       $s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
       $s3 = "CONNECT %s:%d hTTP/1.1" ascii
       $s4 = "CONNECT %s:%d HTTp/1.1" ascii
       $s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
       $s6 = "iphlpapi.dll" ascii
       $s7 = "%systemroot%\\Web\\" ascii
       $s8 = "Proxy-Authorization: Negotiate %s" ascii
       $s9 = "CLSID\\{%s}\\InprocServer32" ascii
   condition:
       ( uint16(0) == 0x5a4d and filesize < 500KB and 5 of them ) or 7 of them
}
rule Codoso_CustomTCP_2 {
   meta:
       description = "Detects Codoso APT CustomTCP Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"
   strings:
       $s1 = "varus_service_x86.dll" fullword ascii
       $s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
       $s3 = "net start %%1" fullword ascii
       $s4 = "ping 127.1 > nul" fullword ascii
       $s5 = "McInitMISPAlertEx" fullword ascii
       $s6 = "sc start %%1" fullword ascii
       $s7 = "B_WKNDNSK^" fullword ascii
       $s8 = "net stop %%1" fullword ascii
   condition:
       uint16(0) == 0x5a4d and filesize < 406KB and all of them
}
rule Codoso_PGV_PVID_6 {
   meta:
       description = "Detects Codoso APT PGV_PVID Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"
   strings:
       $s0 = "rundll32 \"%s\",%s" fullword ascii
       $s1 = "/c ping 127.%d & del \"%s\"" fullword ascii
   condition:
       uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}
rule Codoso_Gh0st_3 {
   meta:
       description = "Detects Codoso APT Gh0st Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"
   strings:
       $x1 = "RunMeByDLL32" fullword ascii

       $s1 = "svchost.dll" fullword wide
       $s2 = "server.dll" fullword ascii
       $s3 = "Copyright ? 2008" fullword wide
       $s4 = "testsupdate33" fullword ascii
       $s5 = "Device Protect Application" fullword wide
       $s6 = "MSVCP60.DLL" fullword ascii /* Goodware String - occured 1 times */
       $s7 = "mail-news.eicp.net" fullword ascii
   condition:
       uint16(0) == 0x5a4d and filesize < 195KB and $x1 or 4 of them
}
rule Codoso_Gh0st_2 {
   meta:
       description = "Detects Codoso APT Gh0st Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
   strings:
       $s0 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
       $s1 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
       $s13 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
       $s14 = "%s -r debug 1" fullword ascii
       $s15 = "\\\\.\\keymmdrv1" fullword ascii
       $s17 = "RunMeByDLL32" fullword ascii
   condition:
       uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}
rule Codoso_CustomTCP {
   meta:
       description = "Codoso CustomTCP Malware"
       author = "Florian Roth"
       reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
       date = "2016-01-30"
       hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"
   strings:
       $s4 = "wnyglw" fullword ascii
       $s5 = "WorkerRun" fullword ascii
       $s7 = "boazdcd" fullword ascii
       $s8 = "wayflw" fullword ascii
       $s9 = "CODETABL" fullword ascii
   condition:
       uint16(0) == 0x5a4d and filesize < 405KB and all of them
}
