import os
from win11toast import toast

def notify_imap_check(fetched_count, phishing_count):
    # Caminho absoluto para o ícone
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    icon_path = os.path.join(base_dir, "web", "favicon.ico")

    # Se o ícone não existir, não o usamos
    if not os.path.exists(icon_path):
        icon_path = None

    toast(
        title="🚨 Alerta de Phishing — NEAP",
        body=f"Foram analisados {fetched_count} e-mails.\n{phishing_count} ameaças detetadas!",
        icon=icon_path
    )