using System;
using System.Diagnostics;

namespace LunaRhythm {
    public class LunaRhythm
    {
        public static readonly string NAME = "LunaRhythm";
        public static readonly string VERSION = "0.0.1";
        public static readonly bool   VERBOSE = false;
        public static bool Enabled { get; set; } = false;

        public static void Main(string[] args)
        {
            LunaRhythm prog = new LunaRhythm();
            prog.Initialize();
            prog.StartCLI();
        }

        public LunaRhythm() {}

        private EventWriter? eventWriter;

        public void Initialize()
        {
            if (Enabled)
            {
                throw new InvalidOperationException("Program already enabled");
            }

            Enabled = true;
            eventWriter = new EventWriter(this);
        }

        public void StartCLI()
        {
            new CLI().Start();
        }

        public void ProcessEvent(string data)
        {
            if(!Enabled)
            {
                throw new InvaldOperationException("Program is disabled");
            }

            if(eventWriter != null)
            {
                throw new InvalidOperationException("Event writer not available");
            }

            eventWriter!.WriteEvent(data);
        }
    }

    public class EventWriter
    {
        public EventWriter(LunaRhythm prog) {
            this.prog = prog;
        }

        LunaRhythm? prog = null;

        public void Initialize()
        {
            if(prog == null || !LunaRhythm.Enabled)
            {
                throw new InvalidOperationException("Program is disabled");
            }

            CreateEventSource_IfNotExists();
        }

        private void CreateEventSource_IfNotExists()
        {
            if(EventLog.SourceExists("LunaRhythm"))
            {
                CLI.Debug("EventWriter", "Event source already exists.");
                return;
            }

            // Create an Event Source named LunaRhythm for
            // Application category logs.
            EventLog.CreateEventSource("LunaRhythm", "Application");
            CLI.Debug("EventWriter", "Event source created.");
        }

        public void WriteEvent(string data)
        {
            //TODO
        }
    }

    public class CLI
    {
        public static bool EnableDebug { get; set; } = false;

        public CLI() {}

        public void Start()
        {
            Info("Welcome to LunaRhythm!");
            CommandLoop();
            Info("Thank you and goodbye.");
        }

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

                if(!continueRunning)
                {
                    break;
                }

                Console.Write("\n");
            }
        }

        private bool CommandInterpret(string input)
        {
            string sanitizedIn = input.ToLower();

            switch(sanitizedIn)
            {
                /*
                 * Exit:
                 * This will exit the CLI.
                 */
                case "exit": case "q": case "quit":
                    Info("Exiting CLI...");
                    return false;
                    /*
                     * Monitor:
                     * This will display real-time logs.
                     */
                case "menu": case "help": case "h":
                    Info("Displaying help menu below.");
                    ShowHelpMenu();
                    break;
                case "monitor": case "mon":
                    Warning("Not implemented!");
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

        private void ShowHelpMenu()
        {
            void ShowHelpMenu_Separator()
            {
                WriteSeparator();
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write(" LunaRhythm Help Menu ");
                WriteSeparator();
                Console.Write("\n");
            }

            void ShowHelpMenu_Item(string name, string descr, string usage)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" \u25aa ");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write(name + ": ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(descr);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("   \xbb ");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Usage: " + usage + "\n");
            }

            Console.Write("\n\n\n");
            ShowHelpMenu_Separator();

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
                    "help, h, menu");

            ShowHelpMenu_Separator();
            Console.Write("\n\n\n");
        }

        private static void WriteSeparator(int length=28)
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
            Console.Write("] \xbb ");
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
            if(!EnableDebug) {
                return;
            }

            Log("DEBUG: " + category, ConsoleColor.Green, obj);
        }
    }
}
