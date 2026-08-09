; ============================================================
;  SENTINEL Agente — Instalador profesional (Inno Setup 6)
;  by ELVIS SYSTEMS Industrias
;
;  Genera un asistente completo (bienvenida, licencia, informacion,
;  carpeta de destino, progreso y finalizacion) y registra el
;  producto en "Agregar o quitar programas" con desinstalador.
;
;  Requisito previo:  build-agent.bat  ->  SENTINEL-Setup.exe
;  Compilar:  ISCC.exe installer\agente.iss
;  Resultado: installer\Output\SENTINEL-Agente-Setup.exe
; ============================================================

#define AppName "SENTINEL Agente"
#define AppVersion "0.1.0"
#define AppPublisher "ELVIS SYSTEMS Industrias"
#define AppURL "https://sentinel-cloud-eight.vercel.app"
#define AgentExe "sentinel-agent.exe"
#define TaskMain "SENTINEL Agente"
#define TaskLogon "SENTINEL Agente Inicio"

[Setup]
AppId={{9F2C4E17-8B3A-4D56-A0E9-1C7B5D2F8A43}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={commonappdata}\SENTINEL
DefaultGroupName=SENTINEL
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName}
OutputDir=Output
OutputBaseFilename=SENTINEL-Agente-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; El agente registra tareas con la cuenta SYSTEM -> requiere elevacion.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
LicenseFile=..\docs\EULA.txt
InfoBeforeFile=INFO-AGENTE.txt
; Evita que quede un proceso del agente bloqueando la desinstalacion.
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
spanish.WelcomeLabel2=Este asistente instalara [name/ver] en su equipo.%n%nSENTINEL supervisa el estado de seguridad de este equipo y permite su mantenimiento remoto desde la consola de administracion.%n%nSe recomienda cerrar el resto de aplicaciones antes de continuar.
spanish.FinishedLabelNoIcons=La instalacion de [name] ha finalizado correctamente.
spanish.FinishedLabel=La instalacion de [name] ha finalizado correctamente.%n%nEl equipo ya reporta su estado a la consola de administracion. El primer reporte se envio durante la instalacion.

[Dirs]
; Carpetas escribibles para la evidencia y la configuracion del equipo.
; El permiso va SOLO en estas subcarpetas: {app} guarda el agente, que corre
; como SYSTEM, y darle escritura a las cuentas normales permitiria sustituir
; el .exe y escalar privilegios.
Name: "{app}\data";   Permissions: users-modify; Flags: uninsneveruninstall
Name: "{app}\config"; Permissions: users-modify; Flags: uninsneveruninstall

[Files]
Source: "..\SENTINEL-Setup.exe"; DestDir: "{app}"; DestName: "{#AgentExe}"; Flags: ignoreversion
Source: "INFO-AGENTE.txt"; DestDir: "{app}"; DestName: "LEEME.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"

[Run]
; --- Tarea periodica: reporta el estado cada 15 minutos ---
Filename: "{sys}\schtasks.exe"; \
  Parameters: "/create /tn ""{#TaskMain}"" /tr ""\""{app}\{#AgentExe}\"" --reportar"" /sc minute /mo 15 /ru SYSTEM /rl HIGHEST /f"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Registrando la tarea de supervision..."

; --- Tarea de inicio de sesion ---
Filename: "{sys}\schtasks.exe"; \
  Parameters: "/create /tn ""{#TaskLogon}"" /tr ""\""{app}\{#AgentExe}\"" --reportar"" /sc onlogon /ru SYSTEM /rl HIGHEST /f"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Registrando la tarea de inicio..."

; --- Primer reporte: el equipo aparece en la consola de inmediato ---
Filename: "{app}\{#AgentExe}"; Parameters: "--reportar"; \
  Flags: runhidden waituntilterminated skipifdoesntexist; \
  StatusMsg: "Enviando el primer reporte a la consola..."

[UninstallRun]
; Retira el filtro de contenido si por cualquier motivo estuviera aplicado.
Filename: "{app}\{#AgentExe}"; Parameters: "--quitar-filtro"; \
  Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "SentinelQuitarFiltro"

; Elimina las dos tareas programadas.
Filename: "{sys}\schtasks.exe"; Parameters: "/delete /tn ""{#TaskMain}"" /f"; \
  Flags: runhidden waituntilterminated; RunOnceId: "SentinelBorrarTarea1"
Filename: "{sys}\schtasks.exe"; Parameters: "/delete /tn ""{#TaskLogon}"" /f"; \
  Flags: runhidden waituntilterminated; RunOnceId: "SentinelBorrarTarea2"

[UninstallDelete]
; Configuracion y datos que el agente pueda haber escrito en su carpeta.
Type: files; Name: "{app}\config.json"
Type: files; Name: "{app}\agente.log"
Type: dirifempty; Name: "{app}"
