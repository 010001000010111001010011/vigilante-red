# Vigilante de Red Casero 🏠👀

Escanea tu red wifi, lista los aparatos conectados y **te avisa cuando
aparece uno desconocido**. Potente y adaptable: aprende tu casa, se
configura fácil y sirve en cualquier wifi hogareño.

## Qué es y qué NO es

**Sí hace:**
- Lista todos los aparatos conectados a tu wifi (IP, MAC, fabricante).
- Aprende cuáles son tus aparatos normales.
- Te alerta con un aviso claro cuando entra uno nuevo.
- Guarda historial: cuándo se vio cada aparato por primera y última vez.
- Puede vigilar solo, escaneando cada tantos minutos.

**NO hace (con honestidad):**
- No es un antivirus: no limpia, no bloquea ni expulsa aparatos.
- No ve dentro de tus aparatos ni lee tu tráfico.
- No funciona si la PC está apagada o en otra red.
- La acción (desconectar algo raro, cambiar la clave) la haces vos en el router.

Solo observa tu red con ping y la tabla ARP. No modifica nada.

## Requisitos

- Python 3.8 o superior.
- Tu PC conectada al mismo wifi que querés vigilar.
- Sin programas extra: usa solo la biblioteca estándar de Python.
- Funciona en Windows y Linux. No necesita permisos de administrador.

## Uso

Abrí una terminal (en Windows: cmd o PowerShell) dentro de la carpeta
del programa.

**1. Primera vez: aprender tu casa**

```bash
python vigilante.py --aprender
```

Esto guarda todos los aparatos encontrados como conocidos.
**Revisa la lista antes de confiar**: si aparece algo que no es tuyo,
borralo del archivo `dispositivos_conocidos.json`.

**2. De ahí en más: escanear**

```bash
python vigilante.py
```

Te muestra la tabla y te avisa con `⚠ NUEVO` si entró algo desconocido.

**3. Si el aparato nuevo sí es tuyo (una tele nueva, un teléfono nuevo)**

```bash
python vigilante.py --aprobar AA:BB:CC:DD:EE:FF
```

**4. Vigilancia continua (cada 30 minutos, por ejemplo)**

```bash
python vigilante.py --vigilar 30
```

Se detiene con `Ctrl+C`.

**Opciones útiles:**

```bash
python vigilante.py --red 192.168.1.0/24   # escanear una red concreta
python vigilante.py --sin-nombres          # escaneo más rápido
```

## Si aparece un aparato desconocido

1. Fíjate en tu casa qué puede ser (¿alguien nuevo? ¿una tele nueva?).
2. Si no es tuyo: cambia la clave del wifi y desconéctalo desde el router.
3. Revisa que tu router no tenga la contraseña de fábrica y que su
   firmware esté actualizado.
4. Si puedes, poné los aparatos inteligentes (teles, cámaras) en la red
   de invitados, separados de tus teléfonos y tu PC.

## Adaptarlo a tu casa

- **Fabricantes**: la tabla `OUI` al principio de `vigilante.py` es
  referencial y ampliable. Si tu aparato sale como "Desconocido",
  agrega su prefijo MAC (los primeros 3 pares) con su nombre.
- **Intervalo**: cambia los minutos de `--vigilar` como quieras.
- **Red**: con `--red` escaneas cualquier red hogareña.
- **Datos**: todo queda en archivos JSON simples en la misma carpeta
  (`dispositivos_conocidos.json`, `ultimo_reporte.json`), fáciles de
  revisar y de borrar.

## Licencia

MIT. Úsalo, modifícalo y compártelo libremente.
