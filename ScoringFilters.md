# Building Score-based Filters


Having the possibility to assign a score for a positive match on the filter or filter condition is a great way to build an evaluation system that can decide what to do with the message or attachment based on the total score. 

To sum up scores, they need to be stored somewhere, but Message Filters neither has the option to create variables nor to compare them. There are Action Variables that can store some of the results, but they are predefined and can not be compared against anything, at least not in a direct way.  For example `$MatcheContent` can be used to log matches from the regular expression that are stored in the list, but we have no option to check the size of that list or compare it in any kind. 

But we can use the message itself to store evaluating results by inserting a custom header, with any value we need. Next, the header value can be compared against keywords from a content dict

## Threshold Scoring 


Taking different actions based on the number of rules that are matched or the number of collected "points" by matching rules with higher weights is possible by using three elements: 
- `insert-header()` -  message filter action
- `header-dictionary-match()` - message filter rule
- content dictionary


### Insert Header Action Rule 

Marking the message with a custom header is a great approach that allows further evaluation of the message. The evaluation can be done by another message or content filter or by another security appliance. 

```
insert-header("header-name","header-value");
```

Please note you can insert multiple headers with the same header name and different values. 

### Dictionary Match Filter Rule

```ruby
header-dictionary-match("<dictionary>", "<header-name>", <N>);
```

The `header-dictionary-match()` rule evaluates to true if:
- message contains header specified in the filter
- header-value matches pattern found  within the dictionary
- pattern matches the minimum number of times as specified by the threshold value

Note:
- header name is case insensitive
- threshold value is optional


### Content Dictionary

The Content Dictionary must include header values on which the scoring system is built. We can weight terms so certain keywords trigger filter rules more easily. 

Content Dictionary can be created either from Web UI or from the CLI: 
- UI: `Mail Policies > Dictionaries > Add Dictionary...` 
- CLI: `DICTIONARYCONFIG > NEW`

For the filter `MF_MacroIOCActions` the following dictionary is used. 


| Term               | Weight |
| ------------------ | ------ |
| MacroKeyClass1     | 3      |
| MacroKeyClass2     | 2      |
| MacroCallKeyClass1 | 3      |
| MacroCallKeyClass2 | 2      |
| MacroCallKeyClass3 | 1      |

You can keep the `Match whole words` option marked under Advanced Matching options. 



## MacroIOCRules Filter

This filter is built for demonstration purposes.  For prod, it may be a better idea to have those rules stored in separate filters and use different header values depending on your approach to scoring. 


```ruby
MF_MacroIOCRules: if (attachment-filename == "(?i)\\.(xls|doc|ppt|xlsx|xlsm|xltm|xlsb|docx|docm|dotm|pptx|ppam|pptm|potm|ppsm|slk)$"){
    if  (attachment-binary-contains("(?i)vba(6|7|Proj)") AND attachment-binary-contains("(?i)versioncompatible32") ) {
        log-entry("MF-MacroIOC: OLE VBA Macro indicator: $MatchedContent found. IOCPoints: 2p");
        insert-header("X-MacroIOC", "MacroKeyClass2");
    }
    else{
        if (attachment-binary-contains("(?i)/VBAProject\\.bin")){
            log-entry("MF-MacroIOC: OOXML VBA Macro indicator: '$MatchedContent' found. IOCPoints: 3p");
            insert-header("X-MacroIOC", "MacroKeyClass1");
        }
        else {
            if  (attachment-binary-contains("(?i)Excel 4.0( Macros)?") OR attachment-binary-contains("(?i)xl/macrosheets") ) {
                log-entry("MF-MacroIOC: XLM - Excel 4.0 Macro indicator: '$MatchedContent' found. IOCPoints: 3p");
                insert-header("X-MacroIOC", "MacroKeyClass1");
            }
        }
    }
    if (attachment-binary-contains("(?i)(Auto|Document|Workbook)(_)?(Open|Close)")){
        log-entry("MF-MacroIOC: Macro AutoExec keyword '$MatchedContent' found. IOCPoints: 3p");
        insert-header("X-MacroIOC", "MacroCallKeyClass1");
    }
    else { 
        if (attachment-binary-contains("(?i)_*Open\\(\\)?")){
            log-entry("MF-MacroIOC: Partial AutoExec keyword: '$MatchedContent' found. IOCPoints: 1p");
            insert-header("X-MacroIOC","MacroCallKeyClass3");
        }
    }
    if (attachment-binary-contains("(?i)(cmd\\.exe|winmgmts:|(rundll32|regsvr32|powershell)(\\.exe)?)")){
            log-entry("MF-MacroIOC: Higly suspicious EXEC keyword: '$MatchedContent' found. IOCPoints: 3p");
            insert-header("X-MacroIOC","MacroCallKeyClass1");
    }
    if (attachment-binary-contains("(?i)(kernel32|user32|advapi32|shell32|RunDll|regsvr32|winsock)(\\.dll)?")){
            log-entry("MF-MacroIOC: Higly suspicious DLL keyword: '$MatchedContent' found. IOCPoints: 3p");
            insert-header("X-MacroIOC","MacroCallKeyClass1");
    }
    if (attachment-binary-contains("(?i)(wininet|winhttp|urlmon|ntdll|imagehlp)(\\.dll)?")){
            log-entry("MF-MacroIOC: Suspicious DLL keyword: '$MatchedContent' found. IOCPoints: 2p");
            insert-header("X-MacroIOC","MacroCallKeyClass2");
    }
}
```

## MacroIOCAction Filter


The filter takes three different decisions based on the minimum threshold value reached by matching header values. For reaching min threshold of 5 "points" the filter appends a warning to the Subject of the message and put the message into quarantine. For 3 "points", the message also Subject gets the warning information but only the copy of the message is sent to quarantine, and for 2 points only the Subject is changed. Please note it is an example of how we can use threshold scoring in taking different decisions. You should adjust the scoring and the action to your preferences. 


```ruby
MF_MacroIOCActions: if (attachment-filename == "(?i)\\.(xls|doc|ppt|xlsx|xlsm|xltm|xlsb|docx|docm|dotm|pptx|ppam|pptm|potm|ppsm|slk)$"){
    if (header-dictionary-match ('MACROKEYS', "X-MacroIOC", 5)){
        log-entry("MF-MacroIOC: Got 5 or more points for having susp MACRO keys: Highly Suspicious Macro > Quarantine");
        strip-header ('Subject');
        insert-header ('Subject', '*** WARNING: Highly Suspicious Attachment *** $Subject');
        quarantine('Policy');
    }
    else {
        if (header-dictionary-match ('MACROKEYS', "X-MacroIOC", 3)){
            log-entry("MF-MacroIOC: Got 3 or more points for having susp MACRO keys: Suspicious Macro > Subject Warning & Copy To Quarantine");
            strip-header ('Subject');
            insert-header ('Subject', '*** WARNING: Suspicious Attachment *** $Subject');  
            duplicate-quarantine('Policy');      
        }
        else {
            if (header-dictionary-match ('MACROKEYS', "X-MacroIOC", 2)){
                log-entry("MF-MacroIOC: Got 2 points for having susp MACRO keys: Possible Macro > Subject Warning");                          
                strip-header ('Subject');
                insert-header ('Subject', '*** WARNING: Suspicious Attachment *** $Subject');
            }
        }
    }
}
```

For MacroIOCRules filter the content dictionary includes 5 keywords or so-called classes to categorize threat indicators. To reach the threshold set with the `header-dictionary-match()` rule quicker the keywords use weights. Weights help to reach the threshold with fewer matches. Instead of matching for example `MacroKeyClass1` three times to reach a threshold value set to 3, it is enough to match this keyword only once as it has assigned weight eq to 3. For the condition with a threshold value set to 5, it is enough to find one header with `MacroKeyClass1` and one header with `MacroCallKeyClass2`. It gives 5 points on two matches only. 

This is just an example, you are free to build your scoring system. It can include fewer or more keywords in the dictionary. This can be done with 3 classes but using 5 classes of keywords allows me to determine the character of the rule that is matched by evaluating only headers without checking the logs. 
