#!/usr/bin/env python3
"""🧪 Test rápido del Port Scanner"""

from scanner import escanear_rango_avanzado
from database import crear_conexion, crear_tablas

def test_rapido():
    print("="*60)
    print("           🧪 TEST RÁPIDO")
    print("="*60)
    print("\nEscaneando localhost puertos 1-100...\n")
    
    conn = crear_conexion("test_escaneos.db")
    crear_tablas(conn)
    print("✅ Base de datos creada")
    
    print("\n🔍 Escaneando...")
    puertos, total, tiempo = escanear_rango_avanzado("127.0.0.1", 1, 100, 50, False)
    
    print("\n" + "="*60)
    print("           📊 RESULTADOS")
    print("="*60)
    print(f"✅ Escaneados: {total}")
    print(f"✅ Abiertos: {len(puertos)}")
    print(f"⏱️  Tiempo: {tiempo:.2f}s")
    
    if puertos:
        print("\n🚪 Puertos abiertos:")
        for p in puertos:
            print(f"   - Puerto {p['puerto']}: {p['servicio']}")
    
    print("\n✨ Test completado!")
    conn.close()

if __name__ == "__main__":
    test_rapido()
