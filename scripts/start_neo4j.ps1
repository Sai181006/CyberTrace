$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$java = Join-Path $projectRoot ".runtime\java21\jdk-21.0.12.1+1-jre\bin\java.exe"
$neo4jHome = Join-Path $projectRoot ".runtime\neo4j\neo4j-community-5.26.31"

if (-not (Test-Path -LiteralPath $java)) {
    throw "Project-local Java 21 runtime is missing: $java"
}
if (-not (Test-Path -LiteralPath $neo4jHome)) {
    throw "Project-local Neo4j runtime is missing: $neo4jHome"
}

$existing = Get-NetTCPConnection -LocalPort 7687 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Neo4j is already listening on bolt://localhost:7687"
    exit 0
}

$arguments = @(
    "-cp",
    "$neo4jHome\lib\*",
    "-Dbasedir=$neo4jHome",
    "org.neo4j.server.startup.Neo4jCommand",
    "console"
)
$stdout = Join-Path $projectRoot ".runtime\neo4j-server.stdout.log"
$stderr = Join-Path $projectRoot ".runtime\neo4j-server.stderr.log"
$process = Start-Process -FilePath $java -ArgumentList $arguments `
    -WorkingDirectory $neo4jHome -WindowStyle Hidden `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru

$ready = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    try {
        $client = [Net.Sockets.TcpClient]::new()
        $client.Connect("127.0.0.1", 7687)
        $client.Dispose()
        $ready = $true
        break
    }
    catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $ready) {
    throw "Neo4j failed to start. Review $stderr and $stdout"
}
Write-Host "Neo4j started (PID $($process.Id)) at bolt://localhost:7687"
