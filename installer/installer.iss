; ============================================================
;  SENTINEL — Script de instalador (Inno Setup 6+)
;  by ELVIS SYSTEMS Industrias
;
;  Pasos:
;    1) python build.py            -> genera dist\SENTINEL\
;    2) Abrir este .iss en Inno Setup y "Compile"
;       (o:  iscc installer\installer.iss)
;  Resultado: installer\Output\SENTINEL_Setup.exe
; ============================================================

#define AppName "SENTINEL"
#define AppVersion "0.1.0"
#define AppPublisher "ELVIS SYSTEMS Industrias"
#define AppExe "SENTINEL.exe"

[Setup]
AppId={{B7E5B2A1-5E3D-4C9A-9F21-3E8D1A6C7B02}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=SENTINEL-Escritorio-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
AppVerName={#AppName} {#AppVersion}
AppPublisherURL=https://sentinel-cloud-eight.vercel.app
UninstallDisplayName={#AppName} (Escritorio)
LicenseFile=..\docs\EULA.txt
CloseApplications=yes
RestartApplications=no
; SENTINEL ajusta defensas del sistema (con permiso) -> conviene admin:
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear acceso directo en el escritorio"; GroupDescription: "Adicional:"
Name: "startup"; Description: "Iniciar SENTINEL con Windows (protección continua)"; GroupDescription: "Adicional:"

[Dirs]
; La evidencia NO puede vivir en {app}: Archivos de programa es de solo lectura
; para las cuentas sin privilegios del laboratorio, y la base de auditorias
; moria con "unable to open database file" al exportar un informe.
; users-modify: todas las cuentas del equipo comparten y escriben la misma
; evidencia, que es como se audita un laboratorio (una PC, un historial).
; uninsneveruninstall: desinstalar el producto no borra la evidencia auditada.
;
; El permiso se da SOLO a data\ y config\, nunca a la raiz: ahi se instala el
; agente, que corre como SYSTEM desde una tarea programada. Una cuenta normal
; con escritura en esa carpeta podria reemplazar el .exe y escalar a SYSTEM.
Name: "{commonappdata}\{#AppName}";        Flags: uninsneveruninstall
Name: "{commonappdata}\{#AppName}\data";   Permissions: users-modify; Flags: uninsneveruninstall
Name: "{commonappdata}\{#AppName}\config"; Permissions: users-modify; Flags: uninsneveruninstall

[Files]
; Toma TODO el resultado de PyInstaller (dist\SENTINEL):
Source: "..\dist\SENTINEL\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{commonstartup}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: startup

[Run]
Filename: "{app}\{#AppExe}"; Description: "Abrir SENTINEL ahora"; Flags: nowait postinstall skipifsilent
