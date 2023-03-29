# cisco-email-filters

A collection of Message Filters for Cisco Secure Email Gateway (fka Email Security Appliance) focused on hunting document-based threats. It's a result of the author's research and already known and published methods of detecting and identifying specific files and threats.

These filters are not a replacement for any AV or AMP engine but they can enhance the detection and provide granular visibility at the early stage of the email pipeline. They may provide extra value for researchers and threat hunters.

Filters are usually tested only with a limited number of samples in the lab and may be a subject of false positives as well as false negatives. Before you consider committing any of the filters in production you should first perform your own tests.


Examples of message filters looking for indicators of:

- __Document-based threats__

    - [VBA Hunter](vba/vbahunter.md) filters looking for indicators of VBA macros inside MS Office files

    - [XLM Hunter](xlm/xlmhunter.md) filters looking for indicators of XLM - Excel4.0 macros inside MS Office files

    - [PDF Hunter](pdf/pdfhunter.md) filters looking for suspicious PDF object names (keywords)

    - [OneNote Hunter](one/onenote.md) filters looking for suspicious OneNote documents and embedded files

- __Scripts__

    - [JSHunter](scripts/jshunter.md) detecting JavaScript code

- __Specific threats__

    - [CVE-2023-23397](cve/CVE-2023-23397.md) 


Other: 

-  [Building Score-based Filters](ScoringFilters.md) example of using different components to build a scoring filter

