# Seamless Extracurricular Activities

For our extracurricular activities at Seamless while we're ahead

## Woo Organisation

- Keeping both components apart until they're stable is probably a good idea
  - We need to work out a log format so you can parse and I can log
- Injection Component (LunaJuice)
  - Memphis working on
  - LunaJuice is the smart action
  - LunaLib is the payload
  - Both of these may be renamed because LunaLib feels like it could be better but LunaJuice is and will stay the overall name of the system
- LogRhythm Component
  - Sends logs from event viewer to LogRhythm
  - That's all I have to say for now to be honest
- Repo structure
  - Probably a folder for LunaJuice and a folder for the LogRhythm integration
- Further discussion for everything probably a good idea

## Log Data

### Contains

- Process ID

- Process Name

- Parent PID

- Parent Process Name

- Vendor Message ID (Function call? Stdin?)

- Object Type (VMI in English)

- Object Name (Function name / file name)

- Object (Relevant info)

- Response Code (Success or error, return code etc)

- Status (Status of LunaLib)

- Details (Specific arguments)

- Result (Specific return values / number of bytes)

Other fields populated as relevant

## Memphis's Notes (LunaJuice)

- Try not to touch LunaJuice for now, there's a lot going on and a lot that could randomly break it
- Add functions to change tracking dynamically

## Lachlan's Notes

Recommended file structure

- (root)
  - LunaJuice:    smart action
  - LunaLib:      payload
  - LunaRhythm:   reports logs to LogRhythm
