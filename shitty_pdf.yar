/*
  Scope: Against PDF Malware in Email
  Created 07.06.2021
*/

rule skia_pdf1 {
  meta:
    description = "skia pdf spam"
  strings:
    $x1 = "Skia/PDF m80"
  condition:
    $x1 and (filesize > 50KB and filesize < 329KB)
}

rule shab_pdf1 {
  meta:
    description = "shab pdf spam"
  strings:
    $x1 = "Users/root/Desktop"
    $x2 = "/shab_html"
  condition:
    $x1 and $x2
}

rule url_action_pdf1 {
  meta:
    description = "url action pdf"
  strings:
     $x1 = { 0a2f 5479 7065 202f 4163 7469 6f6e 0a2f 5320 2f55 5249 0a2f 5552 4920 2868 7474 703a 2f2f }
  condition:
    $x1
}
