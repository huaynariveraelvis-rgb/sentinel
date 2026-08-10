"""notify.py — Aviso por correo al operador (entrega de informe, NO exfiltracion).

Manda un correo al PROPIO operador (a su buzon, con los resultados de SU
auditoria autorizada) cuando termina un trabajo o cuando lo pide. Es entrega de
informe/notificacion, no envio de datos de terceros.

Config en config/settings.json -> "notify":
    {
      "smtp_host": "smtp.gmail.com",
      "smtp_port": 587,
      "smtp_user": "tucorreo@gmail.com",
      "smtp_password": "clave-de-aplicacion",   # Gmail: App Password, no la normal
      "email_to": "tucorreo@gmail.com"          # a donde llega el aviso
    }
"""
from __future__ import annotations

import ssl
import smtplib
from email.message import EmailMessage


def configured(cfg: dict | None) -> bool:
    cfg = cfg or {}
    return bool(cfg.get("smtp_host") and cfg.get("smtp_user")
               and cfg.get("smtp_password"))


def send_email(cfg: dict, subject: str, body: str) -> tuple[bool, str]:
    """Envia el aviso. Devuelve (ok, mensaje). No lanza."""
    cfg = cfg or {}
    host = cfg.get("smtp_host")
    port = int(cfg.get("smtp_port", 587) or 587)
    user = cfg.get("smtp_user")
    pwd = cfg.get("smtp_password")
    to = cfg.get("email_to") or user
    if not (host and user and pwd and to):
        return (False, "correo no configurado (notify.smtp_host/user/password en "
                       "settings.json).")

    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=30, context=ctx) as s:
                s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.login(user, pwd)
                s.send_message(msg)
        return (True, f"aviso enviado a {to}")
    except Exception as e:
        return (False, f"no se pudo enviar el correo: {e}")
