@echo off
REM Script per creare la struttura delle cartelle su Windows

echo Creazione struttura cartelle per File Server...
echo ==============================================
echo.

REM Directory base
set BASE_DIR=public

REM Crea la directory base se non esiste
if not exist "%BASE_DIR%" (
    mkdir "%BASE_DIR%"
    echo OK Creata directory base: %BASE_DIR%
) else (
    echo OK Directory base gia' esistente: %BASE_DIR%
)

REM Crea le sottocartelle
echo.
echo Creazione sottocartelle...

if not exist "%BASE_DIR%\css" mkdir "%BASE_DIR%\css"
if not exist "%BASE_DIR%\js" mkdir "%BASE_DIR%\js"
if not exist "%BASE_DIR%\js\vendor" mkdir "%BASE_DIR%\js\vendor"
if not exist "%BASE_DIR%\images" mkdir "%BASE_DIR%\images"
if not exist "%BASE_DIR%\images\icons" mkdir "%BASE_DIR%\images\icons"
if not exist "%BASE_DIR%\fonts" mkdir "%BASE_DIR%\fonts"
if not exist "%BASE_DIR%\docs" mkdir "%BASE_DIR%\docs"
if not exist "%BASE_DIR%\audio" mkdir "%BASE_DIR%\audio"
if not exist "%BASE_DIR%\video" mkdir "%BASE_DIR%\video"
if not exist "%BASE_DIR%\data" mkdir "%BASE_DIR%\data"
if not exist "%BASE_DIR%\downloads" mkdir "%BASE_DIR%\downloads"

echo OK Sottocartelle create

echo.
echo Creazione file di esempio...
echo ============================

REM Crea index.html
if not exist "%BASE_DIR%\index.html" (
    (
        echo ^<!DOCTYPE html^>
        echo ^<html lang="it"^>
        echo ^<head^>
        echo     ^<meta charset="UTF-8"^>
        echo     ^<meta name="viewport" content="width=device-width, initial-scale=1.0"^>
        echo     ^<title^>File Server - Home^</title^>
        echo     ^<!-- CSS puo' essere referenziato senza il percorso completo --^>
        echo     ^<link rel="stylesheet" href="/style.css"^>
        echo ^</head^>
        echo ^<body^>
        echo     ^<div class="container"^>
        echo         ^<h1^>Benvenuto nel File Server^</h1^>
        echo         ^<p^>La struttura delle cartelle e' stata configurata con sottocartelle di default.^</p^>
        echo         
        echo         ^<h2^>Esempi di percorsi:^</h2^>
        echo         ^<ul^>
        echo             ^<li^>^<code^>/style.css^</code^> -^> cercato in ^<code^>/css/style.css^</code^>^</li^>
        echo             ^<li^>^<code^>/app.js^</code^> -^> cercato in ^<code^>/js/app.js^</code^>^</li^>
        echo             ^<li^>^<code^>/logo.png^</code^> -^> cercato in ^<code^>/images/logo.png^</code^>^</li^>
        echo         ^</ul^>
        echo         
        echo         ^<img src="/logo.png" alt="Logo"^>
        echo     ^</div^>
        echo     
        echo     ^<!-- JavaScript puo' essere referenziato senza il percorso completo --^>
        echo     ^<script src="/app.js"^>^</script^>
        echo ^</body^>
        echo ^</html^>
    ) > "%BASE_DIR%\index.html"
    echo OK Creato file: %BASE_DIR%\index.html
)

REM Crea style.css
if not exist "%BASE_DIR%\css\style.css" (
    (
        echo /* File CSS di esempio */
        echo body {
        echo     font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        echo     line-height: 1.6;
        echo     margin: 0;
        echo     padding: 20px;
        echo     background-color: #f5f5f5;
        echo }
        echo.
        echo .container {
        echo     max-width: 800px;
        echo     margin: 0 auto;
        echo     background: white;
        echo     padding: 30px;
        echo     border-radius: 8px;
        echo     box-shadow: 0 2px 4px rgba^(0,0,0,0.1^);
        echo }
        echo.
        echo h1 {
        echo     color: #333;
        echo     margin-bottom: 20px;
        echo }
        echo.
        echo code {
        echo     background: #f0f0f0;
        echo     padding: 2px 6px;
        echo     border-radius: 3px;
        echo     font-family: 'Courier New', monospace;
        echo }
    ) > "%BASE_DIR%\css\style.css"
    echo OK Creato file: %BASE_DIR%\css\style.css
)

REM Crea app.js
if not exist "%BASE_DIR%\js\app.js" (
    (
        echo // File JavaScript di esempio
        echo console.log^('File Server: app.js caricato correttamente!'^);
        echo.
        echo document.addEventListener^('DOMContentLoaded', function^(^) {
        echo     console.log^('Struttura cartelle:'^);
        echo     console.log^('- /css/     -^> per fogli di stile'^);
        echo     console.log^('- /js/      -^> per script JavaScript'^);
        echo     console.log^('- /images/  -^> per immagini'^);
        echo     console.log^('- /docs/    -^> per documenti'^);
        echo     console.log^('- /fonts/   -^> per font web'^);
        echo     
        echo     // Esempio: verifica che l'immagine sia caricata
        echo     const img = document.querySelector^('img[src="/logo.png"]'^);
        echo     if ^(img^) {
        echo         img.addEventListener^('load', ^(^) =^> {
        echo             console.log^('Logo caricato correttamente dalla cartella di default!'^);
        echo         }^);
        echo         img.addEventListener^('error', ^(^) =^> {
        echo             console.log^('Logo non trovato. Assicurati che esista in /images/logo.png'^);
        echo         }^);
        echo     }
        echo }^);
    ) > "%BASE_DIR%\js\app.js"
    echo OK Creato file: %BASE_DIR%\js\app.js
)

REM Crea README.md
if not exist "%BASE_DIR%\docs\README.md" (
    (
        echo # Documentazione File Server
        echo.
        echo ## Struttura delle cartelle
        echo.
        echo Il server utilizza una struttura organizzata con cartelle di default per ogni tipo di file:
        echo.
        echo - `/css/` - Fogli di stile CSS
        echo - `/js/` - File JavaScript
        echo - `/images/` - Immagini ^(PNG, JPG, GIF, etc.^)
        echo - `/fonts/` - Font web ^(WOFF, TTF, etc.^)
        echo - `/docs/` - Documenti ^(PDF, TXT, MD, etc.^)
        echo - `/audio/` - File audio
        echo - `/video/` - File video
        echo - `/data/` - File di dati ^(JSON, CSV, XML^)
        echo - `/downloads/` - Archivi scaricabili ^(ZIP, RAR, etc.^)
        echo.
        echo ## Come funziona
        echo.
        echo Quando richiedi un file, il server:
        echo 1. Cerca prima nel percorso esatto richiesto
        echo 2. Se non trovato, cerca nella cartella di default per quel tipo di file
        echo.
        echo Esempio: `/style.css` viene cercato prima in `/style.css`, poi in `/css/style.css`
    ) > "%BASE_DIR%\docs\README.md"
    echo OK Creato file: %BASE_DIR%\docs\README.md
)

REM Crea config.json
if not exist "%BASE_DIR%\data\config.json" (
    (
        echo {
        echo     "app_name": "File Server",
        echo     "version": "1.0.0",
        echo     "features": {
        echo         "default_folders": true,
        echo         "mime_detection": true,
        echo         "auto_index": true
        echo     },
        echo     "folders": {
        echo         "css": "/css/",
        echo         "js": "/js/",
        echo         "images": "/images/",
        echo         "docs": "/docs/",
        echo         "fonts": "/fonts/"
        echo     }
        echo }
    ) > "%BASE_DIR%\data\config.json"
    echo OK Creato file: %BASE_DIR%\data\config.json
)

REM Crea favicon.ico placeholder
if not exist "%BASE_DIR%\favicon.ico" (
    type nul > "%BASE_DIR%\favicon.ico"
    echo OK Creato placeholder: %BASE_DIR%\favicon.ico
)

echo.
echo Riepilogo struttura creata:
echo ===========================
echo %BASE_DIR%\
echo ├── index.html
echo ├── favicon.ico
echo ├── css\
echo │   └── style.css
echo ├── js\
echo │   ├── app.js
echo │   └── vendor\
echo ├── images\
echo │   └── icons\
echo ├── fonts\
echo ├── docs\
echo │   └── README.md
echo ├── audio\
echo ├── video\
echo ├── data\
echo │   └── config.json
echo └── downloads\

echo.
echo OK Struttura delle cartelle creata con successo!
echo.
echo Prossimi passi:
echo 1. Aggiungi i tuoi file nelle cartelle appropriate
echo 2. Avvia il server con: file_server.exe
echo 3. Accedi a http://localhost:8080
echo.

