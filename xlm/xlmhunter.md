# XLMHunter 

This filter looks for indicators of XLM - Excel4.0 Macros inside the MS Office documents.

The first part of the filter looks for `Excel 4.0` string inside OLE-based (CFBF) documents. It is usually found as `Excel 4.0 Macros`, but note the word `Macros` here depends on the MS Office language used to create the document. With the OOXML files, the only check that can be done on compressed data is to look for the name of the directory where Excel4.0 macros are stored. With the new format, it is `xl/macrosheet`. 

Note: Both names are a subject of obfuscation. 

The XLM macros are stored with cells inside the worksheet. This worksheet is usually set with `hidden` or `veryhidden` attribute. From the detection point of view, it is a good indicator to look for and this is what the second part of the filter is doing. It looks for worksheets with these hidden attributes. 

```ruby
MF_XLMHunter: if  (attachment-filename == "(?i)\\.(xls|xlsb|xlsm|xltm|xlsx)$"){
    if  (attachment-binary-contains("(?i)Excel 4.0( Macros)*") OR attachment-binary-contains("(?i)xl/macrosheets") ) {
        log-entry("MF-XLMHunter: XLM Macro indicator: '$MatchedContent' found.");
    }
    # Looking for hidden macro sheet
    # ==================================
    # 85 00 . . . . . . ((01|02)01|.0101)
    # ===================================
    if (attachment-binary-contains("(\\x85\\x00[\\x00-\\xff]{6}((\\x01|\\x02)\\x01|[\\x00-\\xff]\\x01\\x01)")){
        log-entry("MF-XLMHunter: XLM Macro indicator 2: '$MatchedContent' found");
    }
    
}
```


## Hidden Macro Sheet


The byte value at position 5 in a BOUNDSHEET record set visibility of the sheet:
- visible (0x00) 
- hidden (0x01)
- very hidden (0x02)


```sh
oledump.py -p plugin_biff.py --pluginoptions "-o BOUNDSHEET -a " examples/xlm_macro.xls 
  1:      4096 '\x05DocumentSummaryInformation'
  2:      4096 '\x05SummaryInformation'
  3:     16502 'Workbook'
               Plugin: BIFF plugin 
                 0085     14 BOUNDSHEET : Sheet Information - Excel 4.0 macro sheet, hidden
                  00000000: 69 3C 00 00 01 01 06 00  i<......
                  00000008: 4D 61 63 72 6F 31        Macro1
                 0085     14 BOUNDSHEET : Sheet Information - worksheet or dialog sheet, visible
                 ' 00000000: E0 3E 00 00 00 00 06 00  \xe0>......'
                  00000008: 53 68 65 65 74 31        Sheet1

```

If we know what to look for, tools like grep can be used as well. 

```sh
xxd -p examples/xlm_macro.xls | tr -d '\n' | grep -E "8500.{12}((01|02)01|.{2}0101)" --color -o
85000e00693c00000101

1  2  3  4  5  6  7  8  9  10
^  ^  .  .  .  .  .  .  ^  ^
85 00 0e 00 69 3c 00 00 01 01
                        ^
                        hidden
```


```sh
LC_ALL=C grep -oaP -m5  "(\x85\x00[\x00-\xff]{6}((\\x01|\\x02)\\x01)|[\x00-\xff]{1}(\\x01\\x01))" examples/xlm_macro.xls | hexdump -C 

00000000  2c 01 01 0a 04 01 01 0a  00 01 01 0a 00 01 01 0a  |,...............|
00000010  00 01 01 0a 00 01 01 0a  85 00 0e 00 69 3c 00 00  |............i<..|
00000020  01 01 0a                                          |...|
00000023
```
