# VBAHunter

This filter looks for indicators of VBA macros insdie MS Office document files. It looks for specific strings and bytes in Ole-based (CFBF) and for filenames inside OOXML-based files. In addition it evaluates files against known AutoExec function names. 

__Note__: VBA macros with OOXML files are stored in seperate file inside the ZIP container (eg. word/vbaProject.bin) and the message filters have no capability to extract these files. The search that can be done here is limited because we are operating on compressed data. But with ZIP files we can at least search for files by names or paths inside embedded strings. 


```ruby
MF_VBAHunter: if (attachment-filename == "(?i)\\.(xls|doc|ppt|xlsx|xlsm|xltm|xlsb|docx|docm|dotm|pptx|ppam|pptm|potm|ppsm)$") {
    ## Attribute VB_Name in OLE
    if (attachment-binary-contains("(\\x41|\\x61)\\x74\\x74\\x72\\x69\\x62\\x75\\x74(\\x00)*\\x65\\x20(\\x56|\\x76)(\\x42|\\x62)\\x5f(\\x4e|\\x6e)\\x61\\x6d(\\x00)*\\x65\\x20\\x3d") ){
        log-entry("MF-VBAHunter: VBA Macro indicator '$MatchedContent' found");
        #insert-header("X-Macro", "True");
    }
    ## VBA in OLE
    if ( (attachment-binary-contains("(?i)vba(6|7|Proj)") AND (attachment-binary-contains("(?i)versioncompatible32")) )) {
        log-entry("MF-VBAHunter: OLE VBA Macro indicator: '$MatchedContent' found");
        #insert-header("X-Macro", "True");
    }
    ## VBA in OOXML
    if (attachment-binary-contains("(?i)/VBAProject\\.bin")){
        log-entry("MF_VBAHunter: OOXML VBA Macro indicator: '$MatchedContent' found!");
        #insert-header("X-Macro", "True");
    }
    ## AutoExec functions
    if (attachment-binary-contains("(?i)(Auto|Document|Workbook)(_)*(Open|Close)")){
        log-entry("MF-VBAHunter: Macro AutoExec keyword '$MatchedContent' found!");
    }
}
```


Sample #1: non-malicious, word, vba

```
Info: MID 140465 attachment 'vba_macro.doc'
..
Info: MID 140465 Custom Log Entry: MF-VBAHunter: VBA Macro indicator 'vba_macro.doc, Attribut\x00e VB_Nam\x00e =' found
Info: MID 140465 Custom Log Entry: MF-VBAHunter: OLE VBA Macro indicator: 'vba_macro.doc, Attribut\x00e VB_Nam\x00e =, VBA6, VersionCompatible32' found
Info: MID 140465 Custom Log Entry: MF-VBAHunter: Macro AutoExec keyword 'vba_macro.doc, Attribut\x00e VB_Nam\x00e =, VBA6, VersionCompatible32, Workbook_Open' found!
```

## VBA Module 

Each VBA project consists of at least one module, and each module consists of module header and a module body. The module header is a set of attributes that can be coded but mainly it is generated automtically. The module body stores the actual source code. Each module must have name and that name is stored under the `Attribute VB_Name = ` and so it's a good indicator of the macro to search for.

```
olevba -c --attr vba_macro.doc
olevba 0.60.1 on Python 3.8.13 - http://decalage.info/python/oletools
===============================================================================
FILE: vba_macro.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: vba_macro.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Attribute VB_Name = "ThisDocument"
Attribute VB_Base = "1Normal.ThisDocument"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = True
Attribute VB_Customizable = True
Sub Document_Open()

MsgBox "Hello World", 0, "Run by VBA macro"

End Sub

-------------------------------------------------------------------------------
VBA MACRO Module1.bas
in file: vba_macro.doc - OLE stream: 'Macros/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Attribute VB_Name = "Module1"
```

The "Attribut.e VB_Nam.e" is the one that is easily notable within hex editor. 

```sh 
❯ hexdump -C examples/vba_macro.doc| grep -A2 Attrib
00005eb0  ff ff 00 00 01 22 b0 00  41 74 74 72 69 62 75 74  |....."..Attribut|
00005ec0  00 65 20 56 42 5f 4e 61  6d 00 65 20 3d 20 22 4d  |.e VB_Nam.e = "M|
00005ed0  6f 64 00 75 6c 65 31 22  0a 0a 00 00 00 00 00 00  |od.ule1"........|
--
00007460  e2 b0 00 41 74 74 72 69  62 75 74 00 65 20 56 42  |...Attribut.e VB|
00007470  5f 4e 61 6d 00 65 20 3d  20 22 54 68 69 00 73 44  |_Nam.e = "Thi.sD|
00007480  6f 63 75 6d 65 6e 88 74  22 0a 0a 88 42 61 73 02  |ocumen.t"...Bas.|
```
