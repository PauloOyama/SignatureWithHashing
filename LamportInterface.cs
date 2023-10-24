using System.Numerics;
using System.Security.Cryptography;
using Raylib_CsLo;
using signature;

namespace ui;

class LamportInterface
{

    class FileDrop
    {
        Rectangle rect;
        string? currentFilePath = null;
        string? currentFileName = null;

        private static readonly Color onColor = Raylib.DARKGREEN;
        private static readonly Color offColor = Raylib.BLACK;

        public bool HasFile { get => currentFilePath != null; }
        public string CurrentFilePath { get => currentFilePath ?? ""; }
        public string CurrentFileName { get => currentFileName ?? ""; }

        public FileDrop(Rectangle r)
        {
            rect = r;
        }

        public void CheckForFiles()
        {
            if (Raylib.IsFileDropped())
            {
                var mousePos = Raylib.GetMousePosition();
                if (Raylib.CheckCollisionPointRec(mousePos, rect))
                {
                    var droppedFiles = Raylib.GetDroppedFilesAndClear();
                    if (droppedFiles.Length == 0)
                        return;

                    currentFilePath = droppedFiles[0];
                    currentFileName = Path.GetFileName(currentFilePath);
                }
            }
        }

        public void Draw(int fontSize)
        {
            Raylib.DrawRectangleLinesEx(rect, fontSize / 4, currentFileName == null ? offColor : onColor);
            var offset = new Vector2(Raylib.MeasureText(currentFileName ?? "EMPTY", fontSize) / 2, fontSize/2);
            Raylib.DrawText(currentFileName ?? "EMPTY", rect.X + rect.width / 2 - offset.X, rect.Y + rect.height / 2 - offset.Y, fontSize, currentFileName == null ? offColor : onColor);
        }

        public void Clear()
        {
            currentFilePath = null;
            currentFileName = null;
        }
    }

    enum UIState
    {
        SIGN,
        VERIFY
    };

    static LamportSigner signer;
    static LamportVerifier verifier;

    // Both States
    static Rectangle signButtonRec = new Rectangle(
        300 - 40, 320, 80, 30
    );

    static Rectangle changeModeRec = new Rectangle(
        550, 20, 20, 20
    );

    // Sign State
    static FileDrop fileToSign = new FileDrop(
        new Rectangle(
            200, 150, 200, 80
        )
    );

    // Verify State
    static FileDrop messageDrop = new FileDrop(
        new Rectangle(
            200, 90, 200, 80
        )
    );

    static FileDrop pubkeyDrop = new FileDrop(
        new Rectangle(
            90, 210, 200, 80
        )
    );

    static FileDrop signatureDrop = new FileDrop(
        new Rectangle(
            300, 210, 200, 80
        )
    );

    static void UpdateAndDraw(ref UIState state)
    {
        switch (state)
        {
            case UIState.VERIFY:
            {
                Raylib.DrawText("Lamport Verifier", 215, 20, 20, Raylib.BLACK);
                messageDrop.CheckForFiles();
                pubkeyDrop.CheckForFiles();
                signatureDrop.CheckForFiles();
                Raylib.DrawText("Message:", 200, 68, 20, Raylib.BLACK);
                messageDrop.Draw(20);
                Raylib.DrawText("Public Key:", 90, 188, 20, Raylib.BLACK);
                pubkeyDrop.Draw(20);
                Raylib.DrawText("Signature:", 300, 188, 20, Raylib.BLACK);
                signatureDrop.Draw(20);

                if (RayGui.GuiButton(signButtonRec, "Verify!"))
                {
                    if (messageDrop.HasFile && pubkeyDrop.HasFile && signatureDrop.HasFile)
                    {
                        bool validated = verifier.ValidateSignatureFromFiles(
                            messageDrop.CurrentFilePath,
                            pubkeyDrop.CurrentFilePath,
                            signatureDrop.CurrentFilePath
                        );

                        if (validated)
                        {
                            Console.WriteLine("INFO: Signature verified! The message came from the sender!");
                        }
                        else
                        {
                            Console.WriteLine("INFO: Invalid signature for the given message!");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"WARN: Missing files!");
                    }
                }

                if (RayGui.GuiButton(changeModeRec, "#61#"))
                {
                    messageDrop.Clear();
                    pubkeyDrop.Clear();
                    signatureDrop.Clear();
                    state = UIState.SIGN;
                }
            }
            break;
            default: // SIGN
            {
                Raylib.DrawText("Lamport Signer", 220, 20, 20, Raylib.BLACK);
                fileToSign.CheckForFiles();
                fileToSign.Draw(20);

                if (RayGui.GuiButton(signButtonRec, "Sign!"))
                {
                    if (fileToSign.HasFile)
                    {
                        signer.Init();
                        var sign = signer.SignFile(fileToSign.CurrentFilePath);
                        signer.DumpSig(sign!, $"{fileToSign.CurrentFileName}.sig");
                        signer.DumpPublicKey($"{fileToSign.CurrentFileName}.pub");
                        Console.WriteLine($"INFO: File signed.");
                        Console.WriteLine($"INFO: Files {fileToSign.CurrentFileName}.sig and {fileToSign.CurrentFileName}.pub created.");
                    }
                    else
                    {
                        Console.WriteLine("WARN: No file given!");
                    }
                }

                if (RayGui.GuiButton(changeModeRec, "#61#"))
                {
                    fileToSign.Clear();
                    state = UIState.VERIFY;
                }
            }
            break;
        }
    }

    static void Main()
    {
        Raylib.InitWindow(600, 400, "Demonstration - Lamport Signing");
        Raylib.SetTargetFPS(60);

        UIState currentState = UIState.SIGN;
        HashAlgorithm hashFunc = SHA256.Create();
        signer = new LamportSigner(hashFunc);
        verifier = new LamportVerifier(hashFunc);
        
        Console.WriteLine("\n");

        // Verify State fileDroppers
        // FileDrop message = new FileDrop()

        while(!Raylib.WindowShouldClose())
        {
            // if (Raylib.IsFileDropped())
            // {
            //     var droppedFiles = Raylib.GetDroppedFilesAndClear();
            //     droppedFiles.ToList().ForEach((string s) => {Console.WriteLine($"File dropped: {s}");});
            //     var mousePos = Raylib.GetMousePosition();
            //     Console.WriteLine($"Mouse: ({mousePos.X},{mousePos.Y})");
            // }

            Raylib.BeginDrawing();
            Raylib.ClearBackground(Raylib.WHITE);

            UpdateAndDraw(ref currentState);

            // int fontSize = 20;
            // Vector2 offset = new Vector2(Raylib.MeasureText("Badabingus.", fontSize) / 2, fontSize/2);
            // Raylib.DrawText("Badabingus.", 400 - offset.X, 200 - offset.Y, fontSize, Raylib.BLACK);
            Raylib.EndDrawing();
        }

        Raylib.CloseWindow();
    }


}