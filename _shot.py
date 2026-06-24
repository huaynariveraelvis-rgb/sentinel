"""Renderiza el Command Center de SENTINEL en una ventana QtWebEngine real
y la captura a PNG, para previsualizar el reskin sin lanzar toda la app."""
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtCore import QUrl, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWebEngineWidgets import QWebEngineView

base = Path(__file__).resolve().parent
index = base / "assets" / "command_center" / "index.html"
out = base / "_ui_preview" / "sentinel_ui.png"
out.parent.mkdir(exist_ok=True)

app = QApplication.instance() or QApplication(sys.argv)
win = QMainWindow()
win.setWindowTitle("SENTINEL — preview")
win.resize(1200, 780)
view = QWebEngineView()
try:
    view.page().setBackgroundColor(QColor("#05100c"))
except Exception:
    pass
win.setCentralWidget(view)
view.setUrl(QUrl.fromLocalFile(str(index.absolute())))
win.show()
win.raise_()
win.activateWindow()


def grab():
    try:
        import mss, mss.tools
        g = win.frameGeometry()
        dpr = win.devicePixelRatioF()
        region = {
            "left": int(g.x() * dpr), "top": int(g.y() * dpr),
            "width": int(g.width() * dpr), "height": int(g.height() * dpr),
        }
        with mss.mss() as s:
            img = s.grab(region)
            mss.tools.to_png(img.rgb, img.size, output=str(out))
        print("SHOT_OK", out)
    except Exception as e:
        print("SHOT_ERR", e)
    app.quit()


QTimer.singleShot(5000, grab)
QTimer.singleShot(9000, app.quit)
app.exec()
