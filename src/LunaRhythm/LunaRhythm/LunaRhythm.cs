using System.Diagnostics;
using System.Runtime.Versioning;

namespace LunaRhythm
{

    public class LunaRhythm
    {
        public static readonly string NAME = "LunaRhythm";
        public static readonly string VERSION = "0.0.1";
        public static readonly bool VERBOSE = false;
        public static bool Enabled { get; set; } = false;

        [SupportedOSPlatform("windows")]
        public static void Main()
        {
            LunaRhythm prog = new();
            prog.Initialize();
            prog.StartCLI();
        }

        public EventWriter? eventWriter;

        [SupportedOSPlatform("windows")]
        public void Initialize()
        {
            if (Enabled)
            {
                throw new InvalidOperationException("Program already enabled");
            }

            Enabled = true;
            eventWriter = new EventWriter();
            eventWriter.Initialize();
        }

        [SupportedOSPlatform("windows")]
        public void StartCLI()
        {
            if (!Enabled)
            {
                throw new InvalidOperationException("Program is not enabled");
            }

            new CLI(this).Initialize();
        }

        //TODO this event needs to be called by LunaJuice.
        [SupportedOSPlatform("windows")]
        public void ProcessEvent(string data, EventLogEntryType type)
        {
            if (!Enabled)
            {
                throw new InvalidOperationException("Program is disabled");
            }

            if (eventWriter != null)
            {
                throw new InvalidOperationException("Event writer not available");
            }

            eventWriter!.WriteEvent(data, type);
        }
    }

    [SupportedOSPlatform("windows")]
    public class EventWriter()
    {

        public Action<string, EventLogEntryType> CLIEventHook { get; set; } = (data, type) => { };
        private readonly EventLog eventLog = new();

        [SupportedOSPlatform("windows")]
        public void Initialize()
        {
            if (!LunaRhythm.Enabled)
            {
                throw new InvalidOperationException("Program is disabled");
            }

            CreateEventSource_IfNotExists();
            eventLog.Source = LunaRhythm.NAME;
        }

        [SupportedOSPlatform("windows")]
        private static void CreateEventSource_IfNotExists()
        {
            if (EventLog.SourceExists(LunaRhythm.NAME))
            {
                CLI.Debug("EventWriter", "Event source already exists.");
                return;
            }

            // Create an Event Source named LunaRhythm for
            // Application category logs.
            EventLog.CreateEventSource(LunaRhythm.NAME, "Application");
            CLI.Debug("EventWriter", "Event source created.");
        }

        public void WriteEvent(string data, EventLogEntryType type)
        {
            // Write to CLI event hook, so the monitor program can read the log.
            CLIEventHook.Invoke(data, type);

            // Write to event log
            eventLog.WriteEntry(data, type);
        }
    }

    public class CLI(LunaRhythm prog)
    {

        private readonly LunaRhythm prog = prog;

        internal static volatile bool _enableDebug = false;
        public static bool EnableDebug
        {
            get { return _enableDebug; }
            set { _enableDebug = value; }
        }

        internal static volatile bool _enableMonitoring = false;
        public static bool EnableMonitoring
        {
            get { return _enableMonitoring; }
            private set { _enableMonitoring = value; }
        }

        [SupportedOSPlatform("windows")]
        public void Initialize()
        {
            InitializeEventHook();

            Info("Welcome to LunaRhythm!");
            CommandLoop();
            Info("Thank you and goodbye.");
        }

        [SupportedOSPlatform("windows")]
        private void InitializeEventHook()
        {
            prog.eventWriter!.CLIEventHook = ProcessEvent;
        }

        private void ProcessEvent(string data, EventLogEntryType type)
        {
            if(!EnableMonitoring)
            {
                return;
            }

            Console.WriteLine($"Event :: Type: '{type}'; Data: '{data}'.");
        }

        [SupportedOSPlatform("windows")]
        private void CommandLoop()
        {
            while (true)
            {
                Info("Main Menu: Awaiting command... (use 'h' for help)");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("\xab /");
                Console.ForegroundColor = ConsoleColor.White;
                string input = Console.ReadLine() ?? "";
                bool continueRunning = CommandInterpret(input.Trim());

                if (!continueRunning)
                {
                    break;
                }

                Console.Write("\n");
            }
        }

        [SupportedOSPlatform("windows")]
        private bool CommandInterpret(string input)
        {
            string sanitizedIn = input.ToLower();

            switch (sanitizedIn)
            {
                /*
                 * Exit:
                 * This will exit the CLI.
                 */
                case "exit":
                case "q":
                case "quit":
                    Info("Exiting CLI...");
                    return false;
                /*
                 * Monitor:
                 * This will display real-time logs.
                 */
                case "man":
                case "manual":
                case "help":
                case "h":
                    Info("Displaying help menu below.");
                    ShowHelpMenu();
                    break;
                case "monitor":
                case "mon":
                    ShowMonitor();
                    break;
                case "debug-fake-events":
                    Task.Run(DebugCmd_CreateFakeEvents);
                    break;
                /*
                 * Default condition:
                 * This will ask the user to enter a recognised command.
                 */
                default:
                    Error($"Invalid command '{input}', please try again.");
                    break;
            }

            return true;
        }

        [SupportedOSPlatform("windows")]
        private void DebugCmd_CreateFakeEvents()
        {
            Info("Creating fake events for the next 10 seconds in the background. You should see these on the Monitor program and Windows Event Viewer.");
            
            for(int i = 0; i < 10; i++)
            {
                Info("Written debug event #" + (i + 1));
                prog.eventWriter!.WriteEvent("Debug " + DateTime.Now, EventLogEntryType.Information);
                Thread.Sleep(500);
            }

            Info("Finished creating fake events.");
        }

        private static void WritePageHeaderFooter(string name)
        {
            WriteSeparator();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.Write($" {name} ");
            WriteSeparator();
            Console.Write("\n");
        }

        public static void Pause(string description = "Press [ENTER] to continue...")
        {
            Console.WriteLine();
            Info(description);
            Console.ReadLine();
            Console.WriteLine();
        }

        private static void ShowMonitor()
        {
            WritePageHeaderFooter($"{LunaRhythm.NAME} Monitor");
            Info("LunaRhythm is now monitoring for events.");
            EnableMonitoring = true;
            Pause("Press [ENTER] at any time to exit the monitor.");
            Info("Exiting monitor...");
            EnableMonitoring = false;
            WritePageHeaderFooter($"{LunaRhythm.NAME} Monitor");
        }

        private static void ShowHelpMenu()
        {
            static void ShowHelpMenu_Item(string name, string descr, string usage)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" -> ");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write(name + ": ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(descr);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    > ");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Usage: " + usage + "\n");
            }

            Console.Write("\n\n\n");
            WritePageHeaderFooter($"{LunaRhythm.NAME} Manual");

            ShowHelpMenu_Item(
                    "Monitor",
                    "Display real-time monitor.",
                    "monitor, mon");
            ShowHelpMenu_Item(
                    "Exit",
                    "Exit the CLI program.",
                    "exit, quit, q");
            ShowHelpMenu_Item(
                    "Help",
                    "Show command help for Main Menu.",
                    "man, manual, help, h");

            WritePageHeaderFooter($"{LunaRhythm.NAME} Manual");
            Console.Write("\n\n\n");
        }

        private static void WriteSeparator(int length = 28)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("+" + (new string('-', length)) + "+");
        }

        private static void Log(string prefix, ConsoleColor prefixColor,
                object obj)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LunaRhythm.NAME + " v" + LunaRhythm.VERSION);
            Console.Write(" [");
            Console.ForegroundColor = prefixColor;
            Console.Write(prefix);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("] > ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(obj);
        }

        public static void Info(object obj)
        {
            Log("INFO", ConsoleColor.Blue, obj);
        }

        public static void Warning(object obj)
        {
            Log("WARNING", ConsoleColor.Yellow, obj);
        }

        public static void Error(object obj)
        {
            Log("ERROR", ConsoleColor.Magenta, obj);
        }

        public static void Critical(object obj)
        {
            Log("CRITICAL", ConsoleColor.Red, obj);
        }

        public static void Debug(string category, object obj)
        {
            if (!EnableDebug)
            {
                return;
            }

            Log("DEBUG: " + category, ConsoleColor.Green, obj);
        }
    }
}
