# Batesian demo tape
# Run from the repo root:
#   1. pip install starlette uvicorn httpx
#   2. python testdata/a2a_vulnerable_server.py
#   3. GOOS=linux GOARCH=amd64 go build -o bin/batesian ./cmd/batesian
#   4. docker run --rm -v "${PWD}:/vhs" ghcr.io/charmbracelet/vhs docs/demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 24
Set PlaybackSpeed 1.0
Set TypingSpeed 40ms

# --- intro: show what the tool is ---
Sleep 500ms
Type "./bin/batesian --version"
Enter
Sleep 1.5s

# --- probe: map the attack surface ---
Sleep 300ms
Type "./bin/batesian probe --target http://host.docker.internal:9998 --protocol a2a"
Enter
Sleep 6s

# --- scan: active exploit engine ---
Sleep 500ms
Type "./bin/batesian scan --target http://host.docker.internal:9998 --protocol a2a --timeout 20"
Enter
Sleep 20s

# Hold on final output so viewers can read findings
Sleep 3s
