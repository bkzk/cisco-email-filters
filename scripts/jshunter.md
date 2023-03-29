# JS Hunter 


Collection of rules and filters to detect JavaScript code focused on keywords and language-specific functions commonly used by malicious scripts. 


## Grep Patterns

Look for function and var keywords only:

```sh
grep -aoP 'var [a-zA-Z1-9]+[ ]?=|function [a-zA-Z0-9$]+\([a-zA-Z0-9\$,]*\)' 3a6065/3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one 
var hello =
var content =
var body =
var func =
```

Look for all the patterns used in the filter:

```sh
grep -aoP 'var [a-zA-Z1-9]+[ ]?=|function [a-zA-Z0-9$]+\([a-zA-Z0-9\$,]*\)|(atob|btoa|eval|parseInt|replace|String\.fromCharCode|charCodeAt|toString|unescape)\(|document(\.|\[[\x22\x27])(appendChild|cookie|createElement|getElement|getAttribut|location|removeChild|replaceChild|URL|write)|window(\.|\[[\x22\x27])(document|innerWidth|location|open|setTimeout|setInterval|close)' 3a6065/3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one 
var hello =
var content =
document.getElement
var body =
var func =
replace(
window.close
eval(
```

Those might have a higher chance of false positive verdict: `atob|btoa|replace(` 

## Cisco ESA Message Filter

Note: This script is using `attachment-contains()` rule that can use a threshold value. The threshold value allows to specify a minimum number of times a pattern must be found. This is useful to avoid false positives when looking for some common words. 

This filter uses two conditions looking for `function` and `var` keywords followed by function arguments or variable names. It needs to find 3 functions or 3 var keywords. This is a configurable value and you are encouraged to change it. 

__Note__: Unfortunately at this moment the  `attachment-binary-contains()` can not be used with threshold values, and `attachment-contains()` does not work well with binary data, which makes it problematic to use with files like PDF. If the threshold value is not something that worries you, then go ahead and replace attachment-contains with `attachent-binary-contains` rules. This can increase the detection rate but does not allow us to limit rule match to minimum numbers of patterns that need to be found. 



__Note__: This filter evaluates all attachments (see `if (true)`). It is recommended to limit it to specific file types. 

Here is a list of file types that can contain JS code:


| File Type         | File Description                          |
| ----------------: | ----------------------------------------- |
| js                | JavaScript files                          | 
| html              | HTML files                                |
| css               | CSS files                                 |
| xml               | XML files                                 |
| one/onepkg        | MS OneNote documents                      |
| xlsx/xlsm/xltm/xlsb/docx/docm/dotm/pptx/ppam/pptm/potm/ppsm  | MS Office documents (OOXML)               |
| pdf               | Portabled Document Format                 |
| wsf               | MS Windows Script Files                   |
| vbs/vbe           | MS VBScript and Encoded VBScript files    |     
| hta               | HTML Application files                    |



And all kinds of archives - .zip, .rar, .tar,.gz, .bz2, and so on including .iso. But searching patterns over a compressed file does not make sense, so you can skip those for that type of filter (including OOXML-based files).


```ruby 
# Use as initial condition for all other filters to limit the scope of scan attachments
JSHunter: if ("attachment-filename == "(?i)\\.(js|html|hta|css|xml|one|onepkg|pdf|vbs|wsf)$") {

}
```

Feel free to use the above `attachment-filename` rule as a precondition for the below filters (in place of `if (true)`)


These are two versions of the same filter looking for _function_ and _var_ keywords using threshold-based rules or binary-based rules. The difference between those is explained shortly above. 

```ruby
# Look for min 3 function and var keywords, note the threshold value!
JSHunterSimple: if(true){
    if (
        attachment-contains("function\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*\\(",3) 
        and 
        attachment-contains("var\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*=", 3)
    ){
        log-entry("JSHUnterSmpl: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSFunctionVarKey");
    }
}

# Look for any number of var and function keywords, including binary data
JSHunterSimpleB: if(true){
    if (
        attachment-binary-contains("function\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*\\(") 
        and 
        attachment-binary-contains("var\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*=")
    ){
        log-entry("JSHUnterSmpl: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSFunctionVarKey");
    }
}
```



This is a more comprehensive version looking for commonly used Javascript keywords. 

```ruby
JSHunter: if(true){
    # function\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\x00-\x7F][\w$]*)\s*\(
    if (attachment-contains("function\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*\\(",3) ){
        log-entry("JSHUnter: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSFunctionVarKey");
    }
    # var\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\x00-\x7F][\w$]*)\s*=
    if (attachment-contains("var\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*=",3)){
        log-entry("JSHUnter: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSFunctionVarKey");
    }
    # string manipulation
    if(attachment-binary-contains("(atob|btoa|eval|parseInt|replace|String\\.fromCharCode|charCodeAt|toString|unescape)\\(") ){
        log-entry("JSHUnter: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSStringManipulationKey");
    }
    # object property being accessed in two different ways: square bracket (object["field"]) and dot notation (object.field)
    if (attachment-binary-contains("document(\\.|\\[[\\x22\\x27])(appendChild|cookie|createElement|getElement|getAttribut|location|removeChild|replaceChild|URL|write)")){
        log-entry("JSHUnter: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSDocObjKey");
    }
    if (attachment-binary-contains("window(\\.|\\[[\\x22\\x27])(document|innerWidth|location|open|setTimeout|setInterval|close)")){
        log-entry("JSHUnter: JSScript indicator found: '$MatchedContent'");
        insert-header("X-JSHunter","JSWinObjKey");
    }
}
```

## Optimized version


__Disclaimer__: I try to optimize some of the filters for production use for faster evaluation and resource-saving. These filters are usually harder to read by humans and don't allow us to take different actions or allow us to take fewer actions because of the reduced number of conditions. For granular logging and the possibility to insert different headers aka take different actions based on different _if_ statements use non-optimized filters, and for improved performance use an optimized version. Please note that in some cases optimized filters might be more prone to false positives because we cannot take actions based on multiple headers inserted by different conditions. 



```ruby
JSHunterP: if(true){
    if 
    (
        # function\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\x00-\x7F][\w$]*)\s*\(
        attachment-contains("function\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*\\(",3) 
        or
        # var\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\x00-\x7F][\w$]*)\s*=
        attachment-contains("var\\s+([a-zA-Z_$][0-9a-zA-Z_$]*|[^\\x00-\\x7F][\\w$]*)\\s*=",3)
        or 
        # string manipulation
        attachment-binary-contains("(atob|btoa|eval|parseInt|replace|String\\.fromCharCode|charCodeAt|toString|unescape)\\(")
        or
        # object property being accessed in two different ways: square bracket (object["field"]) and dot notation (object.field)
        attachment-binary-contains("document(\\.|\\[[\\x22\\x27])(appendChild|cookie|createElement|getElement|getAttribut|location|removeChild|replaceChild|URL|write)")
        or
        attachment-binary-contains("window(\\.|\\[[\\x22\\x27])(document|innerWidth|location|open|setTimeout|setInterval|close)")
    )
    {
        # log-entry("JSHUnterP: JSScript indicator(s) found: '$MatchedContent'");
        log-entry("JSHUnterP: JSScript indicator(s) found!");
        insert-header("X-JSHunter","True");
    }
}
```




This sample is perfect for testing the filter, it includes plenty of _var_ and _function_ keywords. 


```log
Tue Mar 28 15:36:14 2023 Info: MID 87 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body ='
Tue Mar 28 15:36:14 2023 Info: MID 87 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval('
Tue Mar 28 15:36:14 2023 Info: MID 87 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval(, document.getElement'
Tue Mar 28 15:36:14 2023 Info: MID 87 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval(, document.getElement, window.close'

Tue Mar 28 15:36:14 2023 Info: MID 87 Custom Log Entry: JSHUnterP: JSScript indicator(s) found: 'var hello =, var co tent =, var body ='
```

Note the difference between `JSHunter` and `JSHunterP`. The second stops on first match becors of OR comparision operator. 

## Testbed

Set:

|                                                   SHA256 | Script Type | Filter: OneNoteHunter*| Filter: JSHUnter* | 
| :-------------------------------------------------------------------  | :-------: | --------------------- | ----------------- |
| 3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.one  |  hta    | OneNoteHunter, OneNoteHunterP | JSHunter, JSHunterP |
| a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968.one  |  js     | OneNoteHunter                 | JSHunter, JSHunterP |
| f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb.one  |  hta    | OneNoteHunter, OneNoteHunterP | JSHunter, JSHunterP |





### 3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8

```log 
 Tue Mar 28 15:56:16 2023 Info: MID 89 attachment '3a60658cdbf960c135f07bd06d36124b5926b85c59a9c01948976b199e3959f8.o e'
 Tue Mar 28 15:56:16 2023 Info: ICID 56 close

 Tue Mar 28 15:56:16 2023 Info: MID 89 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body ='
 Tue Mar 28 15:56:16 2023 Info: MID 89 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval('
 Tue Mar 28 15:56:16 2023 Info: MID 89 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval(, document.getElement'
 Tue Mar 28 15:56:16 2023 Info: MID 89 Custom Log Entry: JSHUnter: JSScript indicator found: 'var hello =, var conten  =, var body =, replace(, eval(, document.getElement, window.close'

 Tue Mar 28 15:56:16 2023 Info: MID 89 Custom Log Entry: JSHUnterP: JSScript indicator(s) found: 'var hello =, var co tent =, var body ='
```

#### a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968

```log
 Wed Mar 29 08:08:08 2023 Info: MID 98 attachment 'a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968.one'
 Wed Mar 29 08:08:08 2023 Info: ICID 61 close

 Wed Mar 29 08:08:08 2023 Info: MID 98 Custom Log Entry: JSHUnter: JSScript indicator found: 'function orhBuE6V(, function $PXFL(, function L3ZC('
 Wed Mar 29 08:08:08 2023 Info: MID 98 Custom Log Entry: JSHUnter: JSScript indicator found: 'function orhBuE6V(, function $PXFL(, function L3ZC(, var Bslfjd =, var qXuWH =, v r d8G ='
 Wed Mar 29 08:08:08 2023 Info: MID 98 Custom Log Entry: JSHUnter: JSScript indicator found: 'function orhBuE6V(, function $PXFL(, function L3ZC(, var Bslfjd =, var qXuWH =, v r d8G =, replace('
 
 Wed Mar 29 08:08:08 2023 Info: MID 98 Custom Log Entry: JSHUnterP: JSScript indicator(s) found: 'function orhBuE6V(, function $PXFL(, function L3ZC('
```

#### f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb

```log
 Wed Mar 29 09:57:25 2023 Info: MID 135 attachment 'f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb.one'
 Wed Mar 29 09:57:25 2023 Info: ICID 80 close
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunter: Attachment is OneNote document
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunter: Onenote includes embedded files
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunter: Script indicator found: 'f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb.one, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xbf\xb \xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, document.getElement, document.getElement'

 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunterSmpl: Attachment is a OneNote document
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunterSmpl: Onenote includes embedded files

 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunterP: Attachment is a OneNote document
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: OneNoteHunterP: Script indicator(s) found: 'f2dc85ac9dec5cb21a57d86a83c777c9afd48ba76f89600e4cd3af1b381865eb.one, \xef\xbf\xbd\x16\xef\xbf\xbd\xef\xbf\xbde&\x11E\xef\xbf\xbd\xef\xb \xbd\xef\xbf\xbdM\x0bz\xef\xbf\xbd\xef\xbf\xbd, document.getElement, document.getElement'

 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: JSHUnter: JSScript indicator found: 'var h3 =, var content =, var body ='
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: JSHUnter: JSScript indicator found: 'var h3 =, var content =, var body =, replace(, replace('
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: JSHUnter: JSScript indicator found: 'var h3 =, var content =, var body =, replace(, replace(, document.getElement, document.getElement'
 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: JSHUnter: JSScript indicator found: 'var h3 =, var content =, var body =, replace(, replace(, document.getElement, document.getElement, window.close, window.close'

 Wed Mar 29 09:57:25 2023 Info: MID 135 Custom Log Entry: JSHUnterP2: JSScript indicator(s) found: 'var h3 =, var content =, var body ='
 ```