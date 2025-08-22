import psutil

def listar_puertos_abiertos():
	print("Puertos abiertos en el sistema:")
	conexiones = psutil.net_connections()
	puertos_abiertos = set()
	for conn in conexiones:
		if conn.status == psutil.CONN_LISTEN:
			puertos_abiertos.add(conn.laddr.port)
	for puerto in sorted(puertos_abiertos):
		print(f"- Puerto {puerto}")

def mostrar_conexiones():
	print("\nConexiones activas:")
	conexiones = psutil.net_connections()
	# Definir el orden de prioridad
	estado_prioridad = {
		psutil.CONN_LISTEN: 0,
		psutil.CONN_ESTABLISHED: 1,
		psutil.CONN_TIME_WAIT: 2
	}
	def prioridad(conn):
		return estado_prioridad.get(conn.status, 3)
	conexiones_ordenadas = sorted(conexiones, key=prioridad)
	for conn in conexiones_ordenadas:
		laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
		raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
		print(f"{conn.type.name} | {laddr} -> {raddr} | Estado: {conn.status}")

if __name__ == "__main__":
	listar_puertos_abiertos()
	mostrar_conexiones()
