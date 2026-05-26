
import threading
import time
import os
import sys
import webview
import uvicorn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.main import app

# ─── Start FastAPI ───
def start_api():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

# ─── Wait for API ───
def wait_for_api():
    import urllib.request
    for _ in range(20):
        try:
            urllib.request.urlopen("http://127.0.0.1:8000")
            return True
        except:
            time.sleep(0.5)
    return False

# ─── Main ───
if __name__ == "__main__":
    # Start FastAPI in background thread
    thread = threading.Thread(target=start_api, daemon=True)
    thread.start()

    print("Starting NEAP API...")
    wait_for_api()
    print("API ready!")

    # Get index.html path
    index = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "web", "index.html"
    )

    # Open PyWebView window
    window = webview.create_window(
        title="NEAP — Network Email Anti-Phishing",
        url=f"file:///{index}",
        width=1280,
        height=800,
        min_size=(1024, 600),
        resizable=True,
    )

    webview.start(debug=False)