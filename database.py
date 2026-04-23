import sqlite3
import json
import csv
import os
from datetime import datetime

def crear_conexion(db_path="escaneos.db"):
    return sqlite3.connect(db_path)

def crear_tablas(conn):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS escaneos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            fecha TEXT NOT NULL,
            puertos_escaneados INTEGER,
            puertos_abiertos INTEGER,
            tiempo_escaneo REAL,
            notas TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS puertos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            escaneo_id INTEGER,
            puerto INTEGER,
            estado TEXT,
            servicio TEXT,
            banner TEXT,
            FOREIGN KEY (escaneo_id) REFERENCES escaneos(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            puerto_id INTEGER,
            descripcion TEXT,
            severidad TEXT,
            FOREIGN KEY (puerto_id) REFERENCES puertos(id)
        )
    """)
    conn.commit()

def guardar_escaneo(conn, ip, puertos_escaneados, puertos_abiertos, tiempo_escaneo=None, notas=None):
    cursor = conn.cursor()
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO escaneos (ip, fecha, puertos_escaneados, puertos_abiertos, tiempo_escaneo, notas)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ip, fecha, puertos_escaneados, puertos_abiertos, tiempo_escaneo, notas))
    conn.commit()
    return cursor.lastrowid

def guardar_puerto(conn, escaneo_id, puerto, estado, servicio, banner=None):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO puertos (escaneo_id, puerto, estado, servicio, banner)
        VALUES (?, ?, ?, ?, ?)
    """, (escaneo_id, puerto, estado, servicio, banner))
    conn.commit()
    return cursor.lastrowid

def guardar_vulnerabilidad(conn, puerto_id, descripcion, severidad="Media"):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilidades (puerto_id, descripcion, severidad)
        VALUES (?, ?, ?)
    """, (puerto_id, descripcion, severidad))
    conn.commit()

def ver_historial(conn, limit=20):
    cursor = conn.cursor()
    cursor.execute("SELECT id, ip, fecha, puertos_escaneados, puertos_abiertos, tiempo_escaneo FROM escaneos ORDER BY fecha DESC LIMIT ?", (limit,))
    return cursor.fetchall()

def ver_detalle_escaneo(conn, escaneo_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM escaneos WHERE id = ?", (escaneo_id,))
    escaneo = cursor.fetchone()
    cursor.execute("""
        SELECT p.*, GROUP_CONCAT(v.descripcion, ' | ') as vulnerabilidades
        FROM puertos p
        LEFT JOIN vulnerabilidades v ON p.id = v.puerto_id
        WHERE p.escaneo_id = ?
        GROUP BY p.id
    """, (escaneo_id,))
    puertos = cursor.fetchall()
    return {"escaneo": escaneo, "puertos": puertos}

def obtener_estadisticas(conn):
    cursor = conn.cursor()
    stats = {}
    cursor.execute("SELECT COUNT(*) FROM escaneos")
    stats['total_escaneos'] = cursor.fetchone()[0] or 0
    cursor.execute("SELECT COUNT(*) FROM puertos WHERE estado = 'Abierto'")
    stats['total_puertos_abiertos'] = cursor.fetchone()[0] or 0
    cursor.execute("""
        SELECT servicio, COUNT(*) as count FROM puertos 
        WHERE estado = 'Abierto' GROUP BY servicio 
        ORDER BY count DESC LIMIT 5
    """)
    stats['servicios_comunes'] = cursor.fetchall()
    return stats

def exportar_a_json(conn, escaneo_id, archivo):
    detalle = ver_detalle_escaneo(conn, escaneo_id)
    datos = {"info": detalle["escaneo"], "puertos": [list(p) for p in detalle["puertos"]]}
    with open(archivo, 'w') as f: json.dump(datos, f, indent=4)

def exportar_a_csv(conn, escaneo_id, archivo):
    detalle = ver_detalle_escaneo(conn, escaneo_id)
    with open(archivo, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'ScanID', 'Puerto', 'Estado', 'Servicio', 'Banner', 'Vulns'])
        writer.writerows(detalle["puertos"])

def exportar_a_html(conn, escaneo_id, archivo):
    detalle = ver_detalle_escaneo(conn, escaneo_id)
    esc = detalle["escaneo"]
    html = f"<html><body style='background:#0f172a;color:white;font-family:sans-serif;'><h1>Scan Report: {esc[1]}</h1>"
    html += f"<p>Fecha: {esc[2]} | Abiertos: {esc[4]}</p><table border='1' style='width:100%;border-collapse:collapse;'>"
    html += "<tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Banner</th></tr>"
    for p in detalle["puertos"]:
        color = "#10b981" if p[3] == "Abierto" else "#f59e0b" if p[3] == "Filtrado" else "#64748b"
        html += f"<tr><td>{p[2]}</td><td style='color:{color}'>{p[3]}</td><td>{p[4]}</td><td>{p[5]}</td></tr>"
    html += "</table></body></html>"
    with open(archivo, 'w', encoding='utf-8') as f: f.write(html)