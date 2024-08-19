 // messages.mc 
 // I must end with a newline
 // I must be compiled manually to regenerate headers (right click me in solution explorer)
 // This is the header section.
 // The following are the categories of events.
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_HOOKS                   0x0
#define FACILITY_ABSTRACT                0x2
#define FACILITY_DETAILS                 0x3


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: CAT_STANDARD_FILE
//
// MessageText:
//
// Standard File Operation
//
#define CAT_STANDARD_FILE                ((WORD)0x00000001L)

//
// MessageId: CAT_FUNCTION_CALL
//
// MessageText:
//
// Function Call
//
#define CAT_FUNCTION_CALL                ((WORD)0x00000002L)

//
// MessageId: CAT_PROCESS
//
// MessageText:
//
// Process-Related Event
//
#define CAT_PROCESS                      ((WORD)0x00000003L)

//
// MessageId: CAT_PRIVILEGE
//
// MessageText:
//
// Privilege-Related Event
//
#define CAT_PRIVILEGE                    ((WORD)0x00000004L)

 // The following are the message definitions.
 // 1 = PID
 // 2 = Path
 // 3 = PPID
 // 4 = Origin user
 // 5 = Parent Path
//
// MessageId: MSG_STDIN_READ
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) read data from stdin: %6.
//
#define MSG_STDIN_READ                   ((DWORD)0x40020100L)

//
// MessageId: MSG_STDOUT_WRITE
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) wrote data to stdout: %6.
//
#define MSG_STDOUT_WRITE                 ((DWORD)0x40020101L)

//
// MessageId: MSG_STDERR_WRITE
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) wrote data to stderr: %6.
//
#define MSG_STDERR_WRITE                 ((DWORD)0x40020102L)

//
// MessageId: MSG_FUNCTION_CALL
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) ran function: %6(%7) -> %8.
//
#define MSG_FUNCTION_CALL                ((DWORD)0x40000103L)

//
// MessageId: MSG_SPOOFED_PROCESS
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) ran %6 with PID %7; parameters %8 (fake parent %9).
//
#define MSG_SPOOFED_PROCESS              ((DWORD)0x80020104L)

//
// MessageId: MSG_SPAWN_PROCESS
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) ran %6 with PID %7; parameters %8.
//
#define MSG_SPAWN_PROCESS                ((DWORD)0x40020105L)

 // %6 is either "added" or "removed". %7 is int privilege for now, but will become name
//
// MessageId: MSG_PRIVILEGE_ADJUST
//
// MessageText:
//
// %1 (%2, as %3 from %4 at %5) %6 privilege %7.
//
#define MSG_PRIVILEGE_ADJUST             ((DWORD)0x40020106L)

