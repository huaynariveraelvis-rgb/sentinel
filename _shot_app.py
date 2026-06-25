"""Lanza la app REAL de SENTINEL (ventana + bridge + worker de vigilancia),
espera a que escanee y renderice, y captura la ventana a PNG para verificar
la Fase 1 sin interaccion manual."""
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer, Qt

QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
app = QApplication.instance() or QApplication(sys.argv)
from sentinel.ui.window import SentinelWindow

out = Path(__file__).resolve().parent / "_ui_preview" / "sentinel_live.png"
out.parent.mkdir(exist_ok=True)

win = SentinelWindow(scan_interval=60)
# Forzar al monitor primario (el usuario tiene 2 monitores).
scr = app.primaryScreen().geometry()
win.setGeometry(scr)
win.showNormal()
win.raise_()
win.activateWindow()


def grab():
    try:
        import mss, mss.tools
        g = win.frameGeometry()
        dpr = win.devicePixelRatioF()
        region = {"left": int(g.x()*dpr), "top": int(g.y()*dpr),
                  "width": int(g.width()*dpr), "height": int(g.height()*dpr)}
        with mss.mss() as s:
            img = s.grab(region)
            mss.tools.to_png(img.rgb, img.size, output=str(out))
        print("SHOT_OK", out)
    except Exception as e:
        print("SHOT_ERR", e)
    app.quit()


# 7s: da tiempo a cargar la pagina, conectar el bridge y correr el barrido.
QTimer.singleShot(7000, grab)
QTimer.singleShot(11000, app.quit)
app.exec()
