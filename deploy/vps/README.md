# Coordinador de SENTINEL en tu VPS (aislado, gratis, reversible)

Corre el coordinador del laboratorio en el VPS que ya tienes (el de la pollería),
**sin costo extra** y **sin tocar nada** de polleriajireh.com.

## Garantías

- **No toca** Caddy, jireh-web, los puertos 80/443 ni el firewall.
- **No abre ningún puerto público.** El coordinador se vincula solo a la IP de
  Tailscale (o a `127.0.0.1` si Tailscale no está). Nunca a `0.0.0.0`.
- **Reversible al 100%.** Un script lo retira y el VPS queda igual que antes.
- **Sin dependencias.** El coordinador usa solo la librería estándar de Python;
  no instala paquetes en el sistema.

## Pasos (en el VPS, por SSH)

**1. Instala Tailscale** (gratis) — así el coordinador queda accesible solo por
la VPN, no por internet:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

**2. Sube el proyecto SENTINEL al VPS** (una carpeta cualquiera de tu usuario):

```bash
# opción A: git
git clone <tu-repo> ~/sentinel   # o copia la carpeta con scp

# opción B: scp desde tu PC
# scp -r C:\Users\ELVIS\sentinel usuario@ip-vps:~/sentinel
```

**3. Instala el coordinador:**

```bash
cd ~/sentinel
bash deploy/vps/install-coordinator.sh
```

El script imprime el **TOKEN del laboratorio** y la **IP de Tailscale** del VPS.
Anótalos: ambos van en cada PC del laboratorio.

## Vincular las PCs del laboratorio

En cada PC (con Tailscale instalado y el **mismo token**):

```
python -m sentinel.agent -s http://<ip-tailscale-del-vps>:8770 -e PC-07 --aplicar --ejecutar
```

## Verificar

- Estado del coordinador: `sudo systemctl status sentinel-coord`
- IP para las PCs: `tailscale ip -4`
- Panel (desde cualquier equipo en tu Tailscale): `http://<ip-tailscale-del-vps>:8770/`

## Quitar todo cuando termines

```bash
cd ~/sentinel
bash deploy/vps/uninstall-coordinator.sh
```

El VPS queda como estaba. La pollería nunca se tocó.

---

### ¿Por qué esto no pone en riesgo la pollería?

El único riesgo real de usar el mismo servidor sería **exponer un puerto público
no endurecido**. Este montaje **no expone ningún puerto**: el coordinador solo
escucha en la interfaz de Tailscale (una red privada cifrada). Para el internet,
en el servidor de la pollería no aparece nada nuevo. Si Tailscale llegara a
fallar, el coordinador cae a `127.0.0.1` (solo local) — nunca a algo público.
