namespace LunaRhythm {
    public class LunaRhythm
    {
        public static readonly string NAME = "LunaRhythm";
        public static readonly string VERSION = "0.0.1";

        public static void Main(string[] args)
        {
            new LunaRhythm().StartCLI();
        }

        public LunaRhythm() {}

        public void StartCLI() {
            Console.WriteLine($"{NAME} v{VERSION} \xbb Welcome!");
        }
    }
}
