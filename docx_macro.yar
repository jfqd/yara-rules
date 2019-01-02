/*
  Description: None
  Priority: 5
  Scope: Against Attachment
  Tags: None
  Created in PhishMe's Triage on September 14, 2015 2:35 PM
*/

rule docx_macro
{
  strings:
    $header="PK"
    $vbaStrings="word/vbaProject.bin" nocase
  condition:
    $header at 0 and $vbaStrings
}