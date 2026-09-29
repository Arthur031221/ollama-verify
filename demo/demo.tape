Output demo/demo.gif
Set FontSize 18
Set Width 1100
Set Height 600
Set Theme "Dracula"

Type "ROOT=$(python3 demo/make_fixture.py)"
Enter
Sleep 1s
Type ".venv/bin/ollama-verify scan --root $ROOT --verify"
Enter
Sleep 3s
