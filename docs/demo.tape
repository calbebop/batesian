# Render from PowerShell with ./docs/render-demo.ps1.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 620
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 20ms

Type "./bin/batesian-demo probe --target http://127.0.0.1:3110 --protocol a2a"
Enter
Sleep 3s

Type "clear"
Enter
Sleep 500ms

Type "./bin/batesian-demo scan -t http://127.0.0.1:3110 --protocol a2a --rule-ids a2a-card-security-unenforced-001 --no-config"
Enter
Sleep 5s
