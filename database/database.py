import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__),  'neap.db')



def get_connection():
	conn = sqlite3.connect(DB_PATH)
	conn.execute("PRAGMA foreign_keys = ON")
	return conn

def criar_tabelas():
	conn = get_connection()
	cursor = conn.cursor()
	
	cursor.executescript("""
		CREATE TABLE IF NOT EXISTS EMAILS (
			id_email INTEGER PRIMARY KEY AUTOINCREMENT,
			remetente TEXT NOT NULL,
			assunto TEXT NOT NULL,
			corpo TEXT,
			data_hora DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS ANALISES (
			id_analise INTEGER PRIMARY KEY AUTOINCREMENT,
			id_email INTEGER NOT NULL,
			score INTEGER NOT NULL,
			resultado TEXT NOT NULL,
			nivel_risco TEXT NOT NULL,
			FOREIGN KEY (id_email) REFERENCES EMAILS(id_email)
		);
		
		CREATE TABLE IF NOT EXISTS LOGS (
			id_log INTEGER PRIMARY KEY AUTOINCREMENT,
			id_analise INTEGER NOT NULL,
			data_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
			evento TEXT NOT NULL,
			ip_origem TEXT,
			spf TEXT,
			dkim TEXT,
			dmarc TEXT,
			FOREIGN KEY (id_analise) REFERENCES  ANALISES(id_analise)
		);

		CREATE TABLE IF NOT EXISTS ALERTAS (
			id_alerta INTEGER PRIMARY KEY AUTOINCREMENT,
			id_log INTEGER NOT NULL,
			tipo_alerta TEXT NOT NULL,
			estado_alerta TEXT NOT NULL,
			FOREIGN KEY (id_log) REFERENCES LOGS(id_log)
		);
	""")
	
	conn.commit()
	conn.close()
	print("Tabelas criadas!")

if __name__ == "__main__":
	criar_tabelas()
