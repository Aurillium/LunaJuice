; // messages.mc 
; // I must end with a newline
; // I must be compiled manually to regenerate headers (right click me in solution explorer)

; // This is the header section.


SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )


FacilityNames=(Hooks=0x0:FACILITY_HOOKS
               Abstract=0x2:FACILITY_ABSTRACT
               Details=0x3:FACILITY_DETAILS
              )

LanguageNames=(English=0x409:MSG00409)


; // The following are the categories of events.

MessageIdTypedef=WORD

MessageId=0x1
SymbolicName=CAT_STANDARD_FILE
Language=English
Standard File Operation
.

MessageId=0x2
SymbolicName=CAT_FUNCTION_CALL
Language=English
Function Call
.


; // The following are the message definitions.
; // 1 = PID
; // 2 = Path
; // 3 = PPID
; // 4 = Origin user
; // 5 = Parent Path

MessageIdTypedef=DWORD

MessageId=0x100
Severity=Informational
Facility=Abstract
SymbolicName=MSG_STDIN_READ
Language=English
%1 (%2, as %3 from %4 at %5) read data from stdin: %6.
.


MessageId=0x101
Severity=Informational
Facility=Abstract
SymbolicName=MSG_STDOUT_WRITE
Language=English
%1 (%2, as %3 from %4 at %5) wrote data to stdout: %6.
.

MessageId=0x102
Severity=Informational
Facility=Abstract
SymbolicName=MSG_STDERR_WRITE
Language=English
%1 (%2, as %3 from %4 at %5) wrote data to stderr: %6.
.

MessageId=0x103
Severity=Informational
Facility=Hooks
SymbolicName=MSG_FUNCTION_CALL
Language=English
%1 (%2, as %3 from %4 at %5) ran function: %6(%7) -> %8.
.
