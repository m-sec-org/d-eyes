rule Ransom_Fonix {
   meta:
      description= "Detect the risk of Ransomware Fonix Rule 1"
      hash1 = "79288ff9ff7fd26aabc9b9220c98be69fc50d5962e99f313219c4b2512796d6a"
   strings:
      $x1 = "start cmd.exe /c taskkill /t /f /im sql* && taskkill /f /t /im veeam* && taskkill /F /T /IM MSExchange* && taskkill /F /T /IM Mi" ascii
      $x2 = "start cmd.exe /c taskkill /t /f /im sql* && taskkill /f /t /im veeam* && taskkill /F /T /IM MSExchange* && taskkill /F /T /IM Mi" ascii
      $x3 = "start cmd.exe /c \"C:\\ProgramData\\How To Decrypt Files.hta\" && exit" fullword ascii
      $x4 = "start cmd.exe /c \"C:\\ProgramData\\WindowsUpdate.hta\" && exit" fullword ascii
      $x5 = "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v \"Michael Gillespie\" /t REG_SZ /d C:\\Program" ascii
      $x6 = "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v \"Michael Gillespie\" /t REG_SZ /d C:\\Pro" ascii
      $x7 = "start cmd.exe /c wmic shadowcopy delete " fullword ascii
      $x8 = "start cmd.exe /c bcdedit /set {default} boostatuspolicy ignoreallfailures " fullword ascii
      $x9 = "schtasks /CREATE /SC ONLOGON /TN fonix /TR C:\\ProgramData\\XINOF.exe /RU SYSTEM /RL HIGHEST /F" fullword ascii
      $x10 = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF - 8\" /><title>windowse update</title> <HTA:APPLICATION icon=\"#\" WI" ascii
      $x11 = "C:\\Users\\Phoenix\\Downloads\\cryptopp800\\sse_simd.cpp" fullword ascii
      $x12 = "C:\\Users\\Phoenix\\Downloads\\cryptopp800\\sha_simd.cpp" fullword ascii
      $x13 = "C:\\Users\\Phoenix\\Downloads\\cryptopp800\\chacha_avx.cpp" fullword ascii
      $x14 = "start cmd.exe /c vssadmin Delete Shadows /All /Quiet " fullword ascii
      $x15 = "C:\\Users\\Phoenix\\Downloads\\cryptopp800\\rijndael_simd.cpp" fullword ascii
      $x16 = "start cmd.exe /c icacls * /grant Everyone:(OI)(CI)F /T /C /Q" fullword ascii
      $x17 = "C:\\Users\\Phoenix\\Downloads\\cryptopp800\\chacha_simd.cpp" fullword ascii
      $x18 = "start cmd.exe /c bcdedit /set {default} recoveryenabled no " fullword ascii
      $x19 = "schtasks /CREATE /SC ONLOGON /TN exp /TR C:\\Windows\\explorer.exe  /F" fullword ascii
      $x20 = "schtasks /CREATE /SC ONLOGON /TN fonix /TR C:\\ProgramData\\XINOF.exe /F" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
