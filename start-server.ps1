# Simple HTTP server using PowerShell
# Run: .\start-server.ps1

$port = 8080
$url = "http://localhost:$port/"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Local HTTP Server - mexe" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Starting server on port $port..." -ForegroundColor Yellow
Write-Host ""
Write-Host "Open: $url" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Check whether the port is already in use
$existing = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "WARNING: Port $port is already in use!" -ForegroundColor Red
    Write-Host "Try another port or stop the process currently using port $port." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Do you want to try port 8081? (Y/N)"
    if ($response -eq "Y" -or $response -eq "y") {
        $port = 8081
        $url = "http://localhost:$port/"
    } else {
        exit
    }
}

# Create HTTP listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
$listener.Start()

Write-Host "✅ Server running at $url" -ForegroundColor Green
Write-Host ""

# Helper function: resolve MIME type
function Get-MimeType {
    param($file)
    $ext = [System.IO.Path]::GetExtension($file).ToLower()
    $mimeTypes = @{
        '.html' = 'text/html'
        '.js' = 'text/javascript'
        '.css' = 'text/css'
        '.json' = 'application/json'
        '.png' = 'image/png'
        '.jpg' = 'image/jpeg'
        '.gif' = 'image/gif'
        '.svg' = 'image/svg+xml'
        '.ico' = 'image/x-icon'
        '.manifest' = 'application/manifest+json'
    }
    if ($mimeTypes.ContainsKey($ext)) {
        return $mimeTypes[$ext]
    } else {
        return 'application/octet-stream'
    }
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $localPath = $request.Url.LocalPath
        if ($localPath -eq "/") {
            $localPath = "/index.html"
        }
        
        $filePath = Join-Path $PSScriptRoot $localPath.TrimStart('/')
        
        Write-Host "$($request.HttpMethod) $localPath" -ForegroundColor Gray
        
        if (Test-Path $filePath -PathType Leaf) {
            $content = [System.IO.File]::ReadAllBytes($filePath)
            $mimeType = Get-MimeType $filePath
            
            $response.ContentType = $mimeType
            $response.ContentLength64 = $content.Length
            $response.StatusCode = 200
            $response.OutputStream.Write($content, 0, $content.Length)
        } else {
            $response.StatusCode = 404
            $response.ContentType = 'text/html'
            $notFound = [System.Text.Encoding]::UTF8.GetBytes('<h1>404 - File not found</h1>')
            $response.ContentLength64 = $notFound.Length
            $response.OutputStream.Write($notFound, 0, $notFound.Length)
        }
        
        $response.Close()
    }
} finally {
    $listener.Stop()
    Write-Host ""
    Write-Host "Server stopped." -ForegroundColor Yellow
}
