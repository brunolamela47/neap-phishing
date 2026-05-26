import webview
import uvicorn
import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def start_api():
	uvicorn.run("backend.main:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
	
	thread = threading.Thread(target=start_api, daemon=True)
	thread.start()

	index = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html")
	

	window = webview.create_window(
		title = "NEAP - Network Email Anti Phishing",
		url = f"file:///{index}",
		width = 1280,
		height = 800,
		min_size = (1024, 600),
		resizable = True,
	)

	webview.start()
