import socket
import threading
import random  # Para aleatorizar puertos (Evasión)
import errno
from queue import Queue
from datetime import datetime

# Diccionario expandido de servicios conocidos
SERVICIOS_CONOCIDOS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MS-SQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

VULNERABILIDADES_CONOCIDAS = {
    21: ["FTP anónimo posible", "Credenciales débiles comunes"],
    23: ["Telnet sin cifrado - credenciales en texto plano"],
    3389: ["RDP expuesto - posible blanco de fuerza bruta"],
    445: ["SMB - vulnerable a EternalBlue si no está parcheado"],
    3306: ["MySQL - verificar acceso root sin contraseña"],
    6379: ["Redis - posible acceso sin autenticación"]
}

class PortScanner:
    def __init__(self, num_threads=100, timeout=1, verbose=True):
        self.num_threads = num_threads
        self.timeout = timeout
        self.verbose = verbose
        self.puertos_abiertos = []
        self.lock = threading.Lock()
        self.total_escaneados = 0

    def escanear_puerto(self, ip, puerto):
        """🛡️ Lógica mejorada: Diferencia Abierto, Cerrado y Filtrado"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        
        try:
            resultado = s.connect_ex((ip, puerto))
            servicio = SERVICIOS_CONOCIDOS.get(puerto, "Desconocido")
            
            if resultado == 0:
                banner = self.obtener_banner(s, puerto)
                return True, servicio, banner, "Abierto"
            
            # Si el sistema responde con un RESET, el puerto está cerrado
            elif resultado in [errno.ECONNREFUSED, errno.EHOSTUNREACH]:
                return False, servicio, None, "Cerrado"
            
            # Cualquier otra cosa (como un timeout) suele ser un Firewall filtrando
            else:
                return False, servicio, None, "Filtrado"

        except (socket.timeout, socket.error):
            return False, "Desconocido", None, "Filtrado"
        finally:
            s.close()

    def obtener_banner(self, sock, puerto):
        try:
            sock.settimeout(0.5)
            # Intentar recibir lo que el servidor mande primero
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner: return banner[:100]
            
            # Si no manda nada, forzamos una respuesta según el puerto
            if puerto in [80, 8080]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100]
        except:
            pass
        return None

    def detectar_vulnerabilidades(self, puerto, banner):
        vulnerabilidades = []
        if puerto in VULNERABILIDADES_CONOCIDAS:
            vulnerabilidades.extend(VULNERABILIDADES_CONOCIDAS[puerto])
        if banner:
            b_low = banner.lower()
            if "openssh_5" in b_low or "openssh_4" in b_low:
                vulnerabilidades.append("SSH versión antigua detectada")
        return vulnerabilidades

    def worker(self, ip, queue):
        while True:
            puerto = queue.get()
            if puerto is None: break
            
            # Desempaquetamos los 4 valores que ahora devuelve la función
            abierto, servicio, banner, estado = self.escanear_puerto(ip, puerto)
            
            with self.lock:
                self.total_escaneados += 1
                if abierto:
                    vulns = self.detectar_vulnerabilidades(puerto, banner)
                    self.puertos_abiertos.append({
                        "puerto": puerto, "servicio": servicio, 
                        "banner": banner, "vulnerabilidades": vulns,
                        "estado": estado
                    })
                    if self.verbose:
                        print(f"   ✅ Puerto {puerto} ABIERTO ({servicio})")
                
                # Feedback de progreso (opcional)
                if self.total_escaneados % 100 == 0 and self.verbose:
                    print(f"   📊 Progreso: {self.total_escaneados} puertos analizados...")
            
            queue.task_done()

    def escanear_rango(self, ip, puerto_inicio, puerto_fin):
        self.puertos_abiertos = []
        self.total_escaneados = 0
        
        # 🕵️ MEJORA PURPLE TEAM: Aleatorizar los puertos para evadir firmas de IDS
        lista_puertos = list(range(puerto_inicio, puerto_fin + 1))
        random.shuffle(lista_puertos) 
        
        total_puertos = len(lista_puertos)
        
        if self.verbose:
            print(f"\n🔍 Iniciando Escaneo Stealth en {ip}")
            print(f"⚡ Threads: {self.num_threads} | Puertos: {total_puertos}\n")

        inicio = datetime.now()
        queue = Queue()
        for p in lista_puertos: queue.put(p)

        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.worker, args=(ip, queue))
            t.daemon = True
            t.start()
            threads.append(t)

        queue.join()
        for _ in range(self.num_threads): queue.put(None)
        for t in threads: t.join()

        tiempo_total = (datetime.now() - inicio).total_seconds()
        return self.puertos_abiertos, total_puertos, tiempo_total

# Wrappers para compatibilidad
def escanear_rango_avanzado(ip, p_ini, p_fin, threads=100, verbose=True):
    scanner = PortScanner(num_threads=threads, verbose=verbose)
    return scanner.escanear_rango(ip, p_ini, p_fin)