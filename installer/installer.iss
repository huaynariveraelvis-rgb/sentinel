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
AppId={{B7E5B2A1-5E3D-4C9A-9F21-SENTINEL00001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename={#AppName}_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; SENTINEL ajusta defensas del sistema (con permiso) -> conviene admin:
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear acceso directo en el escritorio"; GroupDescription: "Adicional:"
Name: "startup"; Description: "Iniciar SENTINEL con Windows (protección continua)"; GroupDescription: "Adicional:"

[Files]
; Toma TODO el resultado de PyInstaller (dist\SENTINEL):
Source: "..\dist\SENTINEL\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: startup

[Run]
Filename: "{app}\{#AppExe}"; Description: "Abrir SENTINEL ahora"; Flags: nowait postinstall skipifsilent
