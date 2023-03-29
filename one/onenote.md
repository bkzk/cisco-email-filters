# OneNoteHunter 

This is a collection of rules looking for embedded scripts inside OneNote documents. The filter does not look for any specific campaign but rather for detecting embedded scripts like _.jse_, _.vbe_,_.vbs_, _.wfs_, _.hta_, _.cmd_, _.bat_ or executables PE files.


## OneNote FileDataStoreObject

Embedded file in OneNote document starts with a FileDataStoreObject header represented by: __`E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC`__  


## Grep patterns 

Look for FileDataStoreObject header: 

```sh
LC_ALL=C grep -PoH '\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac' FILENAME
```

Look for FileDataStoreObject header and optionally for known script/pe headers or other indicators:

```sh
LC_ALL=C grep -l -PaoH '\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac(([\x00-\xff]{20})(\x4d\x5a|\x23\x40\x7e\x5e[\x00-\xff]{6}\x3d\x3d|<(job|hta|script)|@?echo off))?' FILENAME 
```

Look only for known embedded scripts/pe:

```sh
LC_ALL=C grep -l  -PaoH '\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac([\x00-\xff]{20})(\x4d\x5a|\x23\x40\x7e\x5e[\x00-\xff]{6}\x3d\x3d|<(job|hta|script)|@?echo off)' FILENAME
```

Look for some random script indicators:

```sh
grep -iE '<(job|hta|script)|echo off|javascript|vbscript|var [a-zA-Z1-9]+[X]?=|function [a-zA-Z0-9$]+\([a-zA-Z0-9\$,]*\)|(CreateObject\()|powershell\.exe' FILENAME
```




## Cisco ESA Message Filter

OneNote documents are not the kind of files that are commonly shared in the corporate world. IMO users usually share a link to a hosted version when they need to collaborate. It is worth considering completely blocking this type of document. 


```ruby
OneNoteDrop: if (true){
    drop-attachments-by-mimetype("application/onenote");
    drop-attachments-by-name("(?i)\\.(one|onepkg)");
    log-entry("OneNoteDrop: Onenote document has been dropped!");
}
```

If dropping OneNotes is not an option go ahead to test the following filters. The only action these filters do is to insert a header. You are free to add any further actions to this or on the next Message or Content Filter. I'd suggest taking an action in another filter based on the header name and/or header value, especially for the OneNoteHunter. 

__Note__: These filters use _$MatchedContent_ action variables. It allows inserting matched content into _mail_logs_, but in production, I'd recommend to skip it. It is great for testing but also adds a lot of noise to _mail_logs_. 


This is a short filter catching OneNote documents with any kind of embedded file inside. 

```ruby
# Filter detects OneNote files with any kind of embedded file(s).
OneNoteHunterSmpl: if (attachment-mimetype == "application/onenote" or attachment-filename == "(?i)\\.(one|onepkg)"   ){
    log-entry("OneNoteHunterSmpl: Attachment is a OneNote document");
    if (attachment-binary-contains("(\\x00)?\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac")){
        log-entry("OneNoteHunterSmpl: Onenote includes embedded files ");
        insert-header("X-OneNoteHunter","True");
    }
}
```


This version is much more specific. It is looking for embedded scripts and executables. 

```ruby
# Filter detects OneNote documents with embedded scripts/executables
OneNoteHunter: if (attachment-mimetype == "application/onenote" or attachment-filename == "(?i)\\.(one|onepkg)"   ){
    log-entry("OneNoteHunter: Attachment is OneNote document");
    insert-header("X-OneNoteHunter","True");
    if (attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac")){
        log-entry("OneNoteHunter: Onenote includes embedded files ");
        # PE: MZ
        # JSE/VBE: #@!^......==
        if (attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac[\\x00-\\xff]{20}(\\x4d\\x5a|\\x23\\x40\\x7e\\x5e[\\x00-\\xff]{6}\\x3d\\x3d)")){
            log-entry("OneNoteHunter: Onenote embeds PE or JSE/VBE script: '$MatchedContent'");
            insert-header("X-OneNoteHunter","PEorVBEorJSE");
        }
        # CMD/BAT: @ECHO OFF, ECHO OFF, @echo off, echo off
        # missing look for `exit /b` at the end of file 
        if (attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac[\\x00-\\xff]{20}(@?(?i)echo off)")){
            log-entry("OneNoteHunter: Onenote embeds CMD/BAT script: '$MatchedContent'");
            insert-header("X-OneNoteHunter","CMDorBAT");
        }
        # WSF: <job
        # usually at the beginning but can be place anywhere 
        if (attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac[\\x00-\\xff]{20,500}((?i)<job )")){
            log-entry("OneNoteHunter: Onenote embeds WSF script: '$MatchedContent'");
            insert-header("X-OneNoteHunter","WSF");
        }
        # HTA: <HTA:, <hta:  
        # this tag can be placed at the beginning or in the head section or be skipped
        if (attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac[\\x00-\\xff]{20,500}((?i)<hta:)")){
            log-entry("OneNoteHunter: Onenote embeds HTA script: '$MatchedContent'");
            insert-header("X-OneNoteHunter","HTA");
        }
        if (attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac[\\x00-\\xff]{20,500}((?i)(<script|javascript|vbscript))")){
            log-entry("OneNoteHunter: Onenote embeds possible HTA/WSF script: '$MatchedContent'");
            insert-header("X-OneNoteHunter","HTAorWSForJS");
        }
        # script indicators (HTA/VBS/WSF)
        if (attachment-binary-contains("(?i)(GetObject\\(|CreateObject\\(|Wscript\\.Shell|ActiveXObject|document\\.(getElement|getAttribut|write)|powershell(\\.exe)?|certutil|FromBase64String|AutoOpen)")){
            log-entry("OneNoteHunter: Script indicator found: '$MatchedContent'");
            insert-header("X-OneNoteHunter","HTAorVBSorWSF");
        }
    }
}
```


Consider to use it together with [JSHunter](../scripts/jshunter.md)


## Optimized version

__Disclaimer__: I try to optimize some of the filters for production use for faster evaluation and resource-saving. These filters are usually harder to read by humans and don't allow us to take different actions or allow us to take fewer actions because of the reduced number of conditions. For granular logging and the possibility to insert different headers aka take different actions based on different _if_ statements use non-optimized filters, and for improved performance use an optimized version. Please note that in some cases optimized filters might be more prone to false positives because we cannot take actions based on multiple headers inserted by different conditions. 


```ruby
OneNoteHunterP: if (
    (
        attachment-mimetype == "application/onenote" or attachment-filename == "(?i)\\.(one|onepkg)"   
    )
    and
    # (FileDataStoreObject ( \.{20}(PE|VBE|CMD-BAT) | \.{20,500}(WSF|HTA|JS|VBS) )
    (
        attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac([\\x00-\\xff]{20}(\\x4d\\x5a|\\x23\\x40\\x7e\\x5e[\\x00-\\xff]{6}\\x3d\\x3d|@?(?i)echo off)|([\\x00-\\xff]{20,500}((?i)<(job|hta:|script|javascript|vbscript))))") 
        or
        (
            # script indicators (HTA/VBS/WSF)
            attachment-binary-contains("\\xe7\\x16\\xe3\\xbd\\x65\\x26\\x11\\x45\\xa4\\xc4\\x8d\\x4d\\x0b\\x7a\\x9e\\xac")
            and
            attachment-binary-contains("(?i)(GetObject\\(|CreateObject\\(|Wscript\\.Shell|ActiveXObject|document\\.(getElement|getAttribut|write)|powershell(\\.exe)?|certutil|FromBase64String|AutoOpen)")
        )
    )
)
{
    log-entry("OneNoteHunterP: Attachment is a OneNote document");
    # log-entry("OneNoteHunterP: Script indicator(s) found: '$MatchedContent'");
    log-entry("OneNoteHunterP: Script indicator(s) found!");
    insert-header("X-OneNoteHunter","True");
}
```

__Note__: There is a slight difference in logic between `OneNoteHunter` and `OneNoteHunterP`. The first one looks for the specific scripts but will also trigger if no scripts are detected but the OneNote document includes an embedded file. It adds an extra log entry (see second condition) in this case. This precondition does not exist in `OneNoteHunterP` filter as a separate condition for other rules, it is used only in that matter for looking at some selected script indicators. The difference can be noted in case we are not able to find any known script indicators. Take a look at `a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968` sample. You may consider using `OneNoteHunterP` with `OneNoteHunterSmpl` to cover this missing part. Please also consider using it with [JSHunter](../scripts/jshunter.md) . 


## Testbed


Set:

|                                                   SHA256 | Script Type | Filter: OneNoteHunter*| Filter: JSHUnter* | 
| :-------------------------------------------------------------------  | :-------: | --------------------- | ----------------- |
| 2623024aba1ee994dcb82e937a8beb59abbebf51b6aa4cde8434bb56458b47da.one  |  vbs    | OneNoteHunter, OneNoteHunterP | - |
| 3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one  |  hta    | OneNoteHunter, OneNoteHunterP | JSHunter, JSHunterP |
| 59d4cf6a9c26bdb1fdfaf38135b591594b5a8f27b570f21d1676dcdf095ba32b.one  |  jse    | OneNoteHunter, OneNoteHunterP | - |
| 62ff7b52aeac2e32e59d8168cd55db1522de07833d476c8e26b36f40724bbebe.one  |  wsf    | OneNoteHunter, OneNoteHunterP | - |
| 76c6f1ac7490a6ff9fe336658c83f25c3b7709922fc39e8018e0e72538509ffe.one  |  wsf    | OneNoteHunter, OneNoteHunterP | - | 
| 9019a31723e8dde778639cf5c1eb599bf250d7b6a3a92ba0e3c85b0043644d93.one  |  cmd    | OneNoteHunter, OneNoteHunterP | - | 
| 9d6cb3b193447e11b2e309b249d07cf3f82a677812e478cec39e2d996d2e8944.one  |  hta    | OneNoteHunter, OneNoteHunterP | - | 
| a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968.one  |  js     | OneNoteHunter                 | JSHunter, JSHunterP |
| aafc0ca9681c1f5c368b0f6da85b90e433f6d62fb34ed2e968e53f83981a800f.one  |  cmd    | OneNoteHunter, OneNoteHunterP | - |
| b13c979dae8236f1e7f322712b774cedb05850c989fc08312a348e2385ed1b21.one  |  exe    | OneNoteHunter, OneNoteHunterP | - |
| b58d332effebce32e00cc254be8561388082e2cdab140fe538bdc3d3ba7f5dcc.one  |  jse    | OneNoteHunter, OneNoteHunterP | - |
| b7f06ac0c97b87147a07ea1471097d84445faff5d13aebc195abb3fbeaa4e526.one  |  wsf    | OneNoteHunter, OneNoteHunterP | - |
| bae645306145f5ca847e16add3371e197b1efbf32c8e63dbb3c14726446ca975.one  |  cmd    | OneNoteHunter, OneNoteHunterP | - |
| e561f7a07ebace71c8de62be6ca6318c1ecd2c39956b4aba07b2149b4a4ebf4a.one  |  wsf    | OneNoteHunter, OneNoteHunterP | - |
| ee1a62d1c2354e54f1763553619159f630f45db3adf53d8970d12d010de3bef5.one  |  wsf    | OneNoteHunter, OneNoteHunterP | - |
| ef5996bf4698ace41405595a4d53a3515ca6041984d6e448c3368c8759837254.one  |  bat    | OneNoteHunter, OneNoteHunterP | - |
| f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb.one  |  hta    | OneNoteHunter, OneNoteHunterP | JSHunter, JSHunterP |
| f8360776618ae88f15187275a0222863ad44565568a71e02626a0ff351e3ef9a.one  |  wsf    | OneNoteHunter, OneNoteHunterP | - |


JavaScript detection script is found here: [JSHunter](../scripts/jshunter.md) 

Results: 


## JSE/VBE

#### 59d4cf6a9c26bdb1fdfaf38135b591594b5a8f27b570f21d1676dcdf095ba32b
```log
ś0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#@~^+gMAAA=='
 ```

#### b58d332effebce32e00cc254be8561388082e2cdab140fe538bdc3d3ba7f5dcc.one (JSE/VBE with #!~^)

```log 
Fri Mar 24 13:52:11 2023 Info: MID 37 attachment 'b58d332effebce32e00cc254be8561388082e2cdab140fe538bdc3d3ba7f5dcc.one'
Fri Mar 24 13:52:11 2023 Info: ICID 29 close
Fri Mar 24 13:52:11 2023 Info: MID 37 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 13:52:11 2023 Info: MID 37 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 13:52:11 2023 Info: MID 37 Custom Log Entry: OneNoteHunter: Onenote embeds PE or JSE/VBE script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\x f\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#@~^DwQAAA=='
 ```

## PE

```log
Fri Mar 24 13:43:22 2023 Info: MID 36 attachment 'b13c979dae8236f1e7f322712b774cedb05850c989fc08312a348e2385ed1b21.one'
Fri Mar 24 13:43:22 2023 Info: ICID 28 close
Fri Mar 24 13:43:31 2023 Info: MID 36 was marked unscannable due to extraction failures. Reason: Error in extraction process.
Fri Mar 24 13:43:31 2023 Warning: MID 36: scanning error (name='universalpostalunion.com', type=executable/exe): perceptive request failed
Fri Mar 24 13:43:39 2023 Warning: MID 36, Message Scanning Problem: Size Limit Exceeded
Fri Mar 24 13:43:42 2023 Warning: MID 36, Message Scanning Problem: Size Limit Exceeded
Fri Mar 24 13:43:46 2023 Warning: MID 36, Message Scanning Problem: Size Limit Exceeded
Fri Mar 24 13:43:50 2023 Warning: MID 36, Message Scanning Problem: Size Limit Exceeded
Fri Mar 24 13:43:54 2023 Warning: MID 36, Message Scanning Problem: Size Limit Exceeded
Fri Mar 24 13:43:58 2023 Info: MID 36 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 13:43:58 2023 Info: MID 36 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 13:43:58 2023 Info: MID 36 Custom Log Entry: OneNoteHunter: Onenote embeds PE or JSE/VBE script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\x f\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd?\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00MZ'
```



## WSF

#### f8360776618ae88f15187275a0222863ad44565568a71e02626a0ff351e3ef9a.one 

```log
Thu Mar 23 16:04:25 2023 Info: MID 21 attachment 'f8360776618ae88f15187275a0222863ad44565568a71e02626a0ff351e3ef9a. ne'
Thu Mar 23 16:04:25 2023 Info: ICID 18 close
Thu Mar 23 16:04:26 2023 Info: MID 21 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Thu Mar 23 16:04:26 2023 Info: MID 21 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Thu Mar 23 16:04:26 2023 Info: MID 21 Custom Log Entry: OneNoteHunter: Onenote embeds WSF script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd|\x01\x00\x00\x00\x 0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<job '
```

#### 62ff7b52aeac2e32e59d8168cd55db1522de07833d476c8e26b36f40724bbebe

```log
Fri Mar 24 17:25:39 2023 Info: MID 49 attachment '62ff7b52aeac2e32e59d8168cd55db1522de07833d476c8e26b36f40724bbebe.one'
Fri Mar 24 17:25:39 2023 Info: MID 49 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:25:39 2023 Info: MID 49 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:25:39 2023 Info: MID 49 Custom Log Entry: OneNoteHunter: Onenote embeds WSF script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \x f\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbdI\xef\xbf\xbd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<job '
Fri Mar 24 17:25:39 2023 Info: MID 49 Custom Log Entry: OneNoteHunter: Onenote embeds possible HTA/WSF script: \'\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbdI\xef\xbf\xbd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<job , \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbdI\xef\xbf\xbd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<job id="cucuparu">\r n<script language="VBScript\'
```


## CMD/BAT

#### aafc0ca9681c1f5c368b0f6da85b90e433f6d62fb34ed2e968e53f83981a800f.one

```log
Thu Mar 23 16:15:15 2023 Info: MID 25 attachment 'aafc0ca9681c1f5c368b0f6da85b90e433f6d62fb34ed2e968e53f83981a800f.one'
Thu Mar 23 16:15:15 2023 Info: ICID 20 close
Thu Mar 23 16:15:15 2023 Info: MID 25 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Thu Mar 23 16:15:15 2023 Info: MID 25 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Thu Mar 23 16:15:15 2023 Info: MID 25 Custom Log Entry: OneNoteHunter: Onenote embeds CMD/BAT script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x0 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00echo off'
```

#### 9019a31723e8dde778639cf5c1eb599bf250d7b6a3a92ba0e3c85b0043644d93
```
 Fri Mar 24 17:27:05 2023 Info: MID 51 attachment '9019a31723e8dde778639cf5c1eb599bf250d7b6a3a92ba0e3c85b0043644d93.one'
 Fri Mar 24 17:27:05 2023 Info: ICID 36 close
 Fri Mar 24 17:27:05 2023 Info: MID 51 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
 Fri Mar 24 17:27:05 2023 Info: MID 51 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
 Fri Mar 24 17:27:05 2023 Info: MID 51 Custom Log Entry: OneNoteHunter: Script indicator found: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, powershell.exe, powershell.exe'
```

#### aafc0c/aafc0ca9681c1f5c368b0f6da85b90e433f6d62fb34ed2e968e53f83981a800f.one
```log
Fri Mar 24 17:31:25 2023 Info: MID 57 attachment 'aafc0ca9681c1f5c368b0f6da85b90e433f6d62fb34ed2e968e53f83981a800f.one'
Fri Mar 24 17:31:25 2023 Info: ICID 39 close
Fri Mar 24 17:31:25 2023 Info: MID 57 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:31:25 2023 Info: MID 57 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:31:25 2023 Info: MID 57 Custom Log Entry: OneNoteHunter: Onenote embeds CMD/BAT script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd  \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00echo off'
```

#### bae645306145f5ca847e16add3371e197b1efbf32c8e63dbb3c14726446ca975
```log
Fri Mar 24 17:33:24 2023 Info: MID 59 attachment 'bae645306145f5ca847e16add3371e197b1efbf32c8e63dbb3c14726446ca975.one'
Fri Mar 24 17:33:24 2023 Info: MID 59 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:33:24 2023 Info: MID 59 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:33:24 2023 Info: MID 59 Custom Log Entry: OneNoteHunter: Onenote embeds CMD/BAT script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd  \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00echo off'
```


## HTA

#### 3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8
```log
Fri Mar 24 17:20:00 2023 Info: MID 43 attachment '3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one'
Fri Mar 24 17:20:00 2023 Info: MID 43 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:20:00 2023 Info: MID 43 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:20:00 2023 Info: MID 43 Custom Log Entry: OneNoteHunter: Onenote embeds possible HTA/WSF script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\x19\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<html><head><sc ipt language="vbscript\'
Fri Mar 24 17:20:00 2023 Info: MID 43 Custom Log Entry: OneNoteHunter: Script indicator found: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\x19\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<html><head><script language="v script, document.getElement, document.getElement, CreateObject(\'
```

#### 9d6cb3b193447e11b2e309b249d07cf3f82a677812e478cec39e2d996d2e8944
```log
 Fri Mar 24 17:28:29 2023 Info: MID 53 attachment '9d6cb3b193447e11b2e309b249d07cf3f82a677812e478cec39e2d996d2e8944.one'
Fri Mar 24 17:28:29 2023 Info: ICID 37 close
Fri Mar 24 17:28:29 2023 Info: MID 53 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:28:29 2023 Info: MID 53 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:28:29 2023 Info: MID 53 Custom Log Entry: OneNoteHunter: Script indicator found: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, document.getElement, document.getElement'
```

#### f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb
```log
Fri Mar 24 17:35:21 2023 Info: MID 61 attachment 'f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb.one'
Fri Mar 24 17:35:21 2023 Info: ICID 41 close
Fri Mar 24 17:35:21 2023 Info: MID 61 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:35:21 2023 Info: MID 61 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:35:21 2023 Info: MID 61 Custom Log Entry: OneNoteHunter: Script indicator found: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, document.getElement, document.getElement'
```



## VBS

#### 2623024aba1ee994dcb82e937a8beb59abbebf51b6aa4cde8434bb56458b47da
```log
Fri Mar 24 17:21:22 2023 Info: MID 45 attachment '2623024aba1ee994dcb82e937a8beb59abbebf51b6aa4cde8434bb56458b47da.one'
Fri Mar 24 17:21:22 2023 Info: ICID 33 close
Fri Mar 24 17:21:22 2023 Info: MID 45 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:21:22 2023 Info: MID 45 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Fri Mar 24 17:21:22 2023 Info: MID 45 Custom Log Entry: OneNoteHunter: Script indicator found: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, Creat Object(, CreateObject(, CreateObject(, CreateObject('
```


## JS 

JavaScript is problematic to catch, especially in case of highly obfuscated script.   

#### a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968

```log 
Fri Mar 24 17:29:57 2023 Info: MID 55 attachment 'a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968.one'
Fri Mar 24 17:29:57 2023 Info: ICID 38 close
Fri Mar 24 17:29:57 2023 Info: MID 55 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Fri Mar 24 17:29:57 2023 Info: MID 55 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
```

Try to use it together with [JSHunter](../scripts/jshunter.md).

```log
 Wed Mar 29 09:35:12 2023 Info: MID 118 attachment 'a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968.one'
 Wed Mar 29 09:35:12 2023 Info: ICID 71 close
 Wed Mar 29 09:35:12 2023 Info: MID 118 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
 Wed Mar 29 09:35:12 2023 Info: MID 118 Custom Log Entry: OneNoteHunter: Onenote includes embedded files

 Wed Mar 29 09:35:12 2023 Info: MID 118 Custom Log Entry: JSHUnter: JSScript indicator found: 'function orhBuE6V(, function $PXFL(, function L3ZC('
 Wed Mar 29 09:35:12 2023 Info: MID 118 Custom Log Entry: JSHUnter: JSScript indicator found: 'function orhBuE6V(, function $PXFL(, function L3ZC(, var Bslfjd =, var qXuWH =, var d8G ='
 Wed Mar 29 09:35:12 2023 Info: MID 118 Custom Log Entry: JSHUnter: JSScript indicator found: 'function orhBuE6V(, function $PXFL(, function L3ZC(, var Bslfjd =, var qXuWH =, var d8G =, replace(, replace('

 Wed Mar 29 09:35:12 2023 Info: MID 118 Custom Log Entry: JSHUnterP: JSScript indicator(s) found: 'function orhBuE6V(, function $PXFL(, function L3ZC('
```


### Perf Tests

Comparing times between `OneNoteHunter`, `OneNoteHunterSmpl`, and optimized `OneNoteHunterP`. 

#### b58d332effebce32e00cc254be8561388082e2cdab140fe538bdc3d3ba7f5dcc

```log
Tue Mar 28 09:37:51 2023 Info: MID 80 attachment 'b58d332effebce32e00cc254be8561388082e2cdab140fe538bdc3d3ba7f5dcc.one'
Tue Mar 28 09:37:51 2023 Info: ICID 51 close
Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunter: Onenote embeds PE or JSE/VBE script: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd'\x04\x00\x00 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#@~^DwQAAA=='

Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunterSmpl: Attachment is a OneNote document
Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunterSmpl: Onenote includes embedded files

Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunterP: Attachment is a OneNote document
Tue Mar 28 09:37:51 2023 Info: MID 80 Custom Log Entry: OneNoteHunterP: Script indicator(s) found: '\xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd'\x04\x00\x00\x00\x0 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#@~^DwQAAA=='
```


```log
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 0.000493288040161
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 6.12735748291e-05
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 4.43458557129e-05
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 4.88758087158e-05
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 3.93390655518e-05
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 4.48226928711e-05
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 0.00110292434692
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunter time: 0.152608156204

Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunterSmpl time: 0.000281572341919
Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunterSmpl time: 0.000543117523193

Tue Mar 28 09:37:51 2023 Info: Debug: MID: 80 Message filter Name: OneNoteHunterP time: 0.000590801239014
```

```sh
cat performance.text.current | ./perflog.py -f - -n OneNoteHunter -m80
MID value: 80
Filter name: OneNoteHunter

Summary:
================================================================================
MID: 80	Message Filter: OneNoteHunter	Total time: 0.15444302558876172 seconds

cat performance.text.current | ./perflog.py -f - -n OneNoteHunterSmpl -m80
MID value: 80
Filter name: OneNoteHunterSmpl

Summary:
================================================================================
MID: 80	Message Filter: OneNoteHunterSmpl	Total time: 0.000824689865112 seconds

cat performance.text.current | ./perflog.py -f - -n OneNoteHunterP -m80
MID value: 80
Filter name: OneNoteHunterP

Summary:
================================================================================
MID: 80	Message Filter: OneNoteHunterP	Total time: 0.000590801239014 seconds
```


#### 3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8

``` log
Tue Mar 28 12:18:39 2023 Info: MID 84 attachment '3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.o e'
Tue Mar 28 12:18:39 2023 Info: ICID 53 close
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunter: Onenote embeds possible HTA/WSF script: \'3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\x19\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x 0\x00\x00\x00\x00\x00<html><head><script language="vbscript\'
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunter: Script indicator found: \'3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\x19\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x 0\x00<html><head><script language="vbscript, document.getElement, document.getElement, CreateObject(\'

Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunterSmpl: Attachment is a OneNote document
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunterSmpl: Onenote includes embedded files

Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body ='
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval('
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval(, document.getElement'
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval(, document.getElement, window.close'

Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunterP: Attachment is a OneNote document
Tue Mar 28 12:18:39 2023 Info: MID 84 Custom Log Entry: OneNoteHunterP: Script indicator(s) found: '3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd\x19\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\ 00\x00\x00<html><head><script'

```

```log 
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 5.1736831665e-05
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 3.79085540771e-05
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 2.88486480713e-05
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 3.5285949707e-05
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 0.000253438949585
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 0.000231027603149
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 0.000884771347046
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunter time: 0.128571748734

Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunterSmpl time: 0.000156402587891
Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunterSmpl time: 0.000320672988892

Tue Mar 28 12:18:39 2023 Info: Debug: MID: 84 Message filter Name: OneNoteHunterP time: 0.00043797492981
```

```sh
cat performance.text.current | ./perflog.py -f - -n OneNoteHunter -m 84
MID value: 84
Filter name: OneNoteHunter

Summary:
================================================================================
MID: 84	Message Filter: OneNoteHunter	Total time: 0.1300947666173004 seconds

cat performance.text.current | ./perflog.py -f - -n OneNoteHunterSmpl -m 84
MID value: 84
Filter name: OneNoteHunterSmpl

Summary:
================================================================================
MID: 84	Message Filter: OneNoteHunterSmpl	Total time: 0.00047707557678300003 seconds

cat performance.text.current | ./perflog.py -f - -n OneNoteHunterP -m84
MID value: 84
Filter name: OneNoteHunterP

Summary:
================================================================================
MID: 84	Message Filter: OneNoteHunterP	Total time: 0.00043797492981 seconds
```


---

Ref: 
 - https://blog.didierstevens.com/2023/01/22/analyzing-malicious-onenote-documents/
 - http://justsolve.archiveteam.org/wiki/OneNote
 - https://blog.talosintelligence.com/emotet-switches-to-onenote/








