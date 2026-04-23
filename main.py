

import os
from scanner import escanear_rango_avanzado
from database import (
    crear_conexion, crear_tablas, guardar_escaneo, 
    guardar_puerto, guardar_vulnerabilidad, ver_historial, 
    ver_detalle_escaneo, exportar_a_json, exportar_a_csv, 
    exportar_a_html, obtener_estadisticas
)

def limpiar_pantalla():
    os.system('clear' if os.name != 'nt' else 'cls')

def mostrar_banner():
    print("\n" + "="*60)
    print("""
    ██████╗ ██████╗ ██████╗ ████████╗    ███████╗ ██████╗  █████╗ ███╗   ██╗
    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝ ██╔══██╗████╗  ██║
    ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║      ███████║██╔██╗ ██║
    ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║      ██╔══██║██║╚██╗██║
    ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗ ██║  ██║██║ ╚████║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
                        v2.0 - Advanced Purple Team Scanner
    """)
    print("="*60)

def mostrar_menu():
    print("\n1. 🔍 Escaneo Rápido (Top Ports)\n2. 🎯 Escaneo Avanzado (Stealth)\n3. 📜 Historial\n4. 🔎 Detalle\n5. 📤 Exportar\n6. 📊 Estadísticas\n7. ❌ Salir")
    return input("\nElegí una opción: ")

def main():
    conn = crear_conexion()
    crear_tablas(conn)
    
    while True:
        limpiar_pantalla()
        mostrar_banner()
        opcion = mostrar_menu()
        
        if opcion in ["1", "2"]:
            ip = input("\n📍 IP objetivo: ")
            inicio = int(input("🚪 Puerto inicio: "))
            fin = int(input("🚪 Puerto fin: "))
            
            # Modo 2 activa Verbose y más Threads
            verbose = True if opcion == "2" else False
            threads = 100 if opcion == "2" else 50
            
            resultados, total, tiempo = escanear_rango_avanzado(ip, inicio, fin, threads, verbose)
            
            # Filtrar solo los que realmente están abiertos para el conteo rápido
            abiertos = [p for p in resultados if p['estado'] == 'Abierto']
            escaneo_id = guardar_escaneo(conn, ip, total, len(abiertos), tiempo)
            
            for p in resultados:
                puerto_id = guardar_puerto(conn, escaneo_id, p["puerto"], p["estado"], p["servicio"], p.get("banner"))
                if p.get("vulnerabilidades"):
                    for vuln in p["vulnerabilidades"]:
                        guardar_vulnerabilidad(conn, puerto_id, vuln)
            
            print(f"\n✅ Escaneo finalizado. ID: {escaneo_id} | Abiertos: {len(abiertos)}")
            input("\n[ENTER]")

        elif opcion == "3":
            historial = ver_historial(conn)
            print(f"\n{'ID':<5} {'IP':<15} {'Fecha':<20} {'Abiertos'}")
            for r in historial: print(f"{r[0]:<5} {r[1]:<15} {r[2]:<20} {r[4]}/{r[3]}")
            input("\n[ENTER]")

        elif opcion == "4":
            idx = int(input("\nID del escaneo: "))
            det = ver_detalle_escaneo(conn, idx)
            if det["escaneo"]:
                for p in det["puertos"]:
                    print(f"Port {p[2]}: {p[3]} ({p[4]}) {'- '+p[6] if p[6] else ''}")
            input("\n[ENTER]")

        elif opcion == "5":
            idx = int(input("\nID a exportar: "))
            formato = input("1.JSON 2.CSV 3.HTML: ")
            if formato == "1": exportar_a_json(conn, idx, f"scan_{idx}.json")
            if formato == "2": exportar_a_csv(conn, idx, f"scan_{idx}.csv")
            if formato == "3": exportar_a_html(conn, idx, f"scan_{idx}.html")
            print("✅ Exportado.")
            input("\n[ENTER]")

        elif opcion == "6":
            st = obtener_estadisticas(conn)
            print(f"\nTotal Scans: {st['total_escaneos']}\nPuertos Abiertos: {st['total_puertos_abiertos']}")
            input("\n[ENTER]")

        elif opcion == "7":
            conn.close()
            break

if __name__ == "__main__":
    main()