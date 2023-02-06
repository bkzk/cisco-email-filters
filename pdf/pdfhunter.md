# PDFHunter 

As a popular and widely "trusted" extension, PDF is still on the radar of malicious actors. PDF is a feature-rich, and well-documented format effective to download and execute malware, steal credentials, or transport other malicious documents like macro-enabled MS Office files.

Basically every piece of information is stored in object. 

```ruby
MF_PDFSuspKeys: if (attachment-filename == "(?i)\\.(pdf)$") AND (attachment-binary-contains("(?i)/(OpenAction|Javascript|Launch|EmbeddedFile|AcroForm)")) {
    log-entry("MF-PDFSuspKeys: '$MatchedContent' string found!");
    insert-header("X-PDF-Macro", "True");
}
```

The above version of the filter is simple to read but has some limitations. First, PDF supports Names Object with hexadecimal or literal characters. This condition operates only on literal characters. Hopefully, Names are case-sensitive so we need to cover only one set of characters in hex. Second, it evaluates to true on the first match which does not give us full visibility in logs.

The sample file that triggers a below log entry might include other keywords but the rule stops at the first match:

```
Info: MID 140173 Custom Log Entry: MF-PDFSuspKeys: 'sample1-6a06f.pdf, /OpenAction' string found!
```


## PDFSuspKeysRules


This is a more comprehensive version that includes a combination of the lateral and hexadecimal representation of characters. Each PDF keyword is evaluated in a separate condition. It inserts a custom header with the value of the keyword it matches. 

```ruby
MF_PDFSuspKeysRules: if (attachment-filename == "(?i)\\.(pdf)$" OR attachment-filetype == "pdf") {

    if (attachment-binary-contains("(?i)/((O|#4f)(p|#70)(e|#65)(n|#6e)(A|#41)(c|#63)(t|#74)(i|#69)(o|#6f)(n|#6e))")) { 
        log-entry("MF-PDFSuspKeys:K1: '$MatchedContent' key found!");
        insert-header("X-PDF-Macro", "OpenAction");
    }
    if (attachment-binary-contains("(?i)/((J|#4a)(a|#61)(v|#76)(a|#61)(s|#73)(c|#63)(r|#72)(i|#69)(p|#70)(t|#74))")) { 
        log-entry("MF-PDFSuspKeys:K2: '$MatchedContent' key found!");
        insert-header("X-PDF-Macro", "JavaScript");
    }
    if (attachment-binary-contains("(?i)/(L|#4c)(a|#61)(u|#75)(n|#6e)(c|#63)(h|#68)")) {         
        log-entry("MF-PDFSuspKeys:K3: '$MatchedContent' key found!");
        insert-header("X-PDF-Macro", "Launch");
    }
    if (attachment-binary-contains("(?i)/(E|#45)(m|#6d)(b|#62)(e|#65)(d|#64)(d|#64)(e|#65)(d|#64)(F|#46)(i|#69)(l|#6c)(e|#65)(s|#73)*")) {
        log-entry("MF-PDFSuspKeys:K4: '$MatchedContent' key found!");
        insert-header("X-PDF-Macro", "EmbeddedFile");
    }
    if (attachment-binary-contains("(?i)/(A|#41)(c|#63)(r|#72)(o|#6f)(F|#46)(o|#6f)(r|#72)(m|#6d)")) {
        log-entry("MF-PDF-SuspKeys:K5: '$MatchedContent' key found!");
        insert-header("X-PDF-Macro", "AcroForm");
    }
    if (attachment-binary-contains("(?i)/(O|#4f)(b|#62)(j|#6a)(S|#53)(t|#74)(m|#6d)")) {
        log-entry("MF-PDFSuspKeys:K6: '$MatchedContent' key found!");
        insert-header("X-PDF-Macro", "ObjStm");
    }
}
```

It catches Names with lateral or hexadecimal representations of characters and their combinations.

__Note__: This filter does not use a complete list of suspicious PDF Names. There is a bunch of others that are worth checking. Just to mention a few of them /GoTo, /GoToR, /GoToE, /URI, or /SubmitForm


The sample1.pdf is used to demonstrate how hexadecimal character can be used together with literal one. 

```
pdf-parser.py smpl1.pdf -o1 -w
obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 3 0 R, 7 0 R
 
<<
 /Type /Catalog
 /Outlines 2 0 R
 /Pages 3 0 R
 /#4Fpen#41ction 7 0 R
>>
```

```
pdf-parser.py smpl1.pdf -o7 -w
obj 7 0
 Type: /Action
 Referencing: 8 0 R
 
<<
 /Type /Action
 /S /J#61v#61Script
 /JS 8 0 R
>>
```


```log
 Info: MID 140591 Custom Log Entry: MF-PDFSuspKeys:K1: 'smpl1.pdf, /#4Fpen#41ction' key found!
 Info: MID 140591 Custom Log Entry: MF-PDFSuspKeys:K2: 'smpl1.pdf, /#4Fpen#41ction, /J#61v#61Script' key found!
```

This can be further used to build a score-based filter.

## PDFSuspKeysActions


The Actions filter uses the same threshold scoring system as introduced in [ScoringFilters](../ScoringFilters.md) document. 

For this filter the following Content Dictionary is used: 

PDFKEYS:

| Term               | Weight |
| ------------------ | ------ |
| JavaScript         | 4      |
| EmbeddedFiles      | 1      |
| EmbeddedFile       | 1      |
| OpenAction         | 3      |
| AcroForm           | 1      |
| Launch             | 3      |
| ObjStm             | 2      |




```ruby
MF_PDFSuspKeyActions: if (attachment-filename == "(?i)\\.(pdf)$" OR attachment-filetype == "pdf") {
    if (header-dictionary-match ('PDFKEYS', "X-PDF-Macro", 4)){
        log-entry("MF-PDFSuspKeys: Got 3 or more points for having susp PDF keys: Highly Suspicious > Quarantine");
        strip-header ('Subject');
        insert-header ('Subject', '*** WARNING: Highly Suspicious Attachment *** $Subject');
        quarantine('Policy');
    }
    else {
        if (header-dictionary-match ('PDFKEYS', "X-PDF-Macro", 3)){
            log-entry("MF-PDFSuspKeys: Got 3 points for having susp PDF keys: Suspicious > Subject Warning");
            strip-header ('Subject');
            insert-header ('Subject', '*** WARNING: Suspicious Attachment *** $Subject');
            duplicate-quarantine('Policy');          
        }
        else {
            if (header-dictionary-match ('PDFKEYS', "X-PDF-Macro", 2)){
                log-entry("MF-PDFSuspKeys: Got 2 points for having susp PDF keys: Somehow Suspicious > Subject Warning");                          
                strip-header ('Subject');
                insert-header ('Subject', '*** WARNING: Suspicious Attachment *** $Subject');
            }
        }
    }
}
```

These two samples are evaluated first by the __PDFSuspKeysRules__ filter that inserts the header and extra log entry, and then by __PDFSuspKeysActions__ that takes the final decision about the message based on the threshold value set by the `header-dictionary-match()` rule. 


- First sample: `smpl1.pdf`

```log 
 Info: MID 140592 Custom Log Entry: MF-PDFSuspKeys:K1: 'smpl1.pdf, /#4Fpen#41ction' key found!
 Info: MID 140592 Custom Log Entry: MF-PDFSuspKeys:K2: 'smpl1.pdf, /#4Fpen#41ction, /J#61v#61Script' key found!
 Info: MID 140592 Custom Log Entry: MF-PDFSuspKeys: Got 3 or more points for having susp PDF keys: Highly Suspicious > Quarantine
 ```

The filter finds /OpenAction and /JavaScript keywords besides both Names are slightly obfuscated by using hex representation of the character. It's old and common trick to bypass lazy build AV signature. 

- Second sample: `mlwr.pdf`

```log
Info: MID 140594 Custom Log Entry: MF-PDFSuspKeys:K1: 'mlwr.pdf, /OpenAction' key found!
Info: MID 140594 Custom Log Entry: MF-PDFSuspKeys:K4: 'mlwr.pdf, /OpenAction, /EmbeddedFile' key f und!
Info: MID 140594 Custom Log Entry: MF-PDF-SuspKeys:K5: 'mlwr.pdf, /OpenAction, /EmbeddedFile, /AcroForm' key found!
Info: MID 140594 Custom Log Entry: MF-PDFSuspKeys:K6: 'mlwr.pdf, /OpenAction, /EmbeddedFile, /AcroForm, /ObjStm' key found!
Info: MID 140594 Custom Log Entry: MF-PDFSuspKeys: Got 3 or more points for having susp PDF keys:  Highly Suspicious > Quarantine
 ```
 
This sample does not include any Javascript code but it includes compressed object names (/ObjStm) and /OpenAction that triggers the form to open /EmbeddedFile on startup.  
 
