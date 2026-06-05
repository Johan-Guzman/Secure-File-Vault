# Secure File Vault
Cifrador y descifrador de archivos con AES-256.

---

## Requisitos previos

- Tener instalado **Java 21** o superior.
- Ejecutar los comandos desde **PowerShell** dentro de la carpeta `src` del proyecto.

---

## Estructura de carpetas recomendada

Antes de empezar, asegúrense de que existan estas dos carpetas dentro del proyecto:

```
Secure-File-Vault/
├── src/
├── encrypt/        <- aquí colocan los archivos que quieren cifrar
└── decrypt/        <- aquí se guardan los archivos descifrados
```

Si no existen, créenlas manualmente o desde PowerShell:

```powershell
mkdir "C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\encrypt"
mkdir "C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\decrypt"
```

---

## Pasos para ejecutar

### 1. Abrir PowerShell y entrar a la carpeta src

```powershell
cd "C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\src"
```

### 2. Activar UTF-8 para que los caracteres se vean correctamente

```powershell
chcp 65001
```

### 3. Compilar el proyecto

```powershell
javac *.java
```

### 4. Ejecutar el programa

```powershell
java Main
```

---

## Uso del programa

Al ejecutarlo verán este menú:

```
=========================================
        SECURE FILE VAULT v1.0
  Cifrador/Descifrador de Archivos AES
=========================================

  [1]  Cifrar un archivo
  [2]  Descifrar un archivo
-----------------------------------------
  Elige una opción (1 o 2):
```

> **Importante:** cuando el programa pida las rutas de los archivos, escríbanlas **sin comillas**.

---

### Cifrar un archivo

Elijan la opción `1` e ingresen los datos así:

```
Elige una opción (1 o 2): 1

Ruta del archivo de entrada : C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\encrypt\documento.txt

Ruta del archivo de salida  : C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\encrypt\documento.enc

Contraseña: (escriben su contraseña, no se verá en pantalla)
```

El archivo cifrado quedará en la carpeta `encrypt` con extensión `.enc`.

---

### Descifrar un archivo

Elijan la opción `2` e ingresen los datos así:

```
Elige una opción (1 o 2): 2

Ruta del archivo de entrada : C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\encrypt\documento.enc

Ruta del archivo de salida  : C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\decrypt\documento.txt

Contraseña: (la misma contraseña que usaron al cifrar)
```

El archivo descifrado quedará en la carpeta `decrypt`.

---

## Errores frecuentes

| Error | Causa | Solución |
|---|---|---|
| `Contraseña incorrecta o archivo corrupto` | Se usó una contraseña distinta a la original | Ingresar la misma contraseña con la que se cifró |
| `Archivo no encontrado` | La ruta del archivo de entrada es incorrecta | Verificar que el archivo exista y que la ruta esté bien escrita |
| `Error de entrada/salida: Acceso denegado` | La ruta de salida apunta a una carpeta, no a un archivo | Asegurarse de incluir el nombre del archivo al final de la ruta de salida |
| Caracteres extraños en pantalla | La terminal no está en UTF-8 | Ejecutar `chcp 65001` antes de correr el programa |

---

## Resumen rápido (comandos en orden)

```powershell
cd "C:\Users\jhonh\Downloads\Proyecto final ciber\Secure-File-Vault\src"
chcp 65001
javac *.java
java Main
```