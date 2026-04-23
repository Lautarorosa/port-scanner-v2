# Port Scanner v2.0 — Advanced Purple Team Scanner

Escáner de puertos multithreaded con detección de vulnerabilidades, banner grabbing y persistencia en SQLite.

## Características

- **Multithreaded** — hasta 100 threads, 10-20x más rápido
- **Detección de estado** — Abierto, Cerrado y Filtrado (firewall)
- **Evasión de IDS** — orden de puertos aleatorio
- **Banner grabbing** — captura de banners HTTP, SSH, FTP, etc.
- **Vulnerabilidades** — mapeo automático por servicio (SMB, RDP, Redis, MySQL...)
- **SQLite** — historial completo de escaneos
- **Exportación** — reportes en JSON, CSV y HTML

## Instalación

```bash
git clone https://github.com/Lautarorosa/port-scanner-v2.git
cd port-scanner-v2
python main.py
```

## Uso

```bash
python main.py        # Menú completo
python test_scanner.py  # Test rápido localhost
```

## Estructura

> Solo para uso educativo. Escanear únicamente sistemas propios o con autorización.