rule EICAR_Test_File {
  meta:
    description = "EICAR antivirus test file"
  strings:
    $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
  condition:
    $a
}

rule Lab_Curl_Pipe_Bash {
  meta:
    description = "Script that downloads and runs code with curl | bash"
  strings:
    $a = "curl" ascii
    $b = /\|\s*(ba)?sh/
  condition:
    $a and $b
}
