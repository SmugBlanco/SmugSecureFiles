#if DEBUG
using SDL2;
using SmugBase.Loading;
using SmugBase.Logging;
using SmugBase.Utility;
#endif

namespace SmugSecureFiles
{
    public class Program
    {
        public const string SecuredExtension = ".ssf";

        public static void Main()
        {
#if DEBUG
            SDL.SDL_Init(0);
            LoadingHandler.ImplementLoading(FileUtility.GetDirectory("SmugSecureFiles", "Logs"));
#endif

            while (true)
            {
                Main main = new Main();
                main.Run();
            }
        }
    }
}