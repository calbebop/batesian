$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$binary = Join-Path $repo 'bin\batesian-demo'
$fixture = 'batesian-demo-fixture'
$containers = @('batesian-demo-build', $fixture, 'batesian-demo-record')

if (Test-Path -LiteralPath $binary) {
    throw "Remove or rename $binary before recording."
}

foreach ($name in $containers) {
    $existing = docker ps -a --filter "name=^/$name$" --format '{{.Names}}'
    if ($LASTEXITCODE -ne 0) { throw 'Could not query Docker containers.' }
    if ($existing) { throw "A container named $name already exists." }
}

try {
    docker run --rm --name batesian-demo-build -v "${repo}:/src" -w /src golang:1.26.10 sh -c 'export PATH=/usr/local/go/bin:$PATH; go build -o bin/batesian-demo ./cmd/batesian'
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the demo CLI.' }
    docker run --rm -d --name $fixture -v "${repo}:/src:ro" -w /src python:3.12-slim sh -c 'pip install --quiet starlette==1.8.0 uvicorn==0.54.0 && python testdata/a2a_card_security_unenforced_server.py'
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the demo fixture.' }

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $ErrorActionPreference = 'Continue'
        docker exec $fixture bash -c 'echo > /dev/tcp/127.0.0.1/3110' *> $null
        $ErrorActionPreference = 'Stop'
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'The demo fixture did not become ready.' }

    docker run --rm --name batesian-demo-record --network "container:$fixture" -v "${repo}:/vhs" ghcr.io/charmbracelet/vhs:v0.12.1 docs/demo.tape
    if ($LASTEXITCODE -ne 0) { throw 'Could not render docs/demo.gif.' }
}
finally {
    $ErrorActionPreference = 'Continue'
    foreach ($name in $containers) { docker stop $name *> $null }
    $ErrorActionPreference = 'Stop'
    if (Test-Path -LiteralPath $binary) {
        Remove-Item -LiteralPath $binary
    }
}
