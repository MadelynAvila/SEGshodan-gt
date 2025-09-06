# SEGshodan-gt
Tarea 4- Shodan
# Proyecto Shodan Guatemala

## Descripción
Este proyecto consiste en un script en **Python** que se conecta a la API de **Shodan** para realizar búsquedas enfocadas en **Guatemala**.  
La idea es aplicar filtros como `city:"Jalapa"` y mostrar en consola los resultados obtenidos, además de generar un resumen con:
- Total de direcciones IP únicas encontradas.
- Total de IPs por puerto abierto.
- Mis datos de estudiante (carné, nombre, curso y sección).

---

## Datos del Estudiante
- **Carné:** 1990-21-11763  
- **Nombre:** Madelyn Yeseenia Lotzoj Avila  
- **Curso:** Seguridad de Redes  
- **Sección:** A  

---

## Pasos realizados
1. Instalé **Python 3.13** en Windows.  
2. Creé un **entorno virtual** con:
   consola
   py -m venv .venv
3. Activé el entorno virtual:
   .\.venv\Scripts\activate
4. Instalé la librería de Shodan:
   pip install shodan
5. Guardé mi API Key de Shodan como variable de entorno:
   setx SHODAN_API_KEY "P5DwYEP3acc43yAGmbsc0IOH0Af8A***"
6. Probé ejecutar el script con mis datos:
   py shodan_gt.py ^
  --filter "city:Jalapa" ^
  --max-results 300 ^
  --carne 1990-21-11763 ^
  --nombre "Madelyn Yeseenia Lotzoj Avila" ^
  --curso "Seguridad de Redes" ^
  --seccion "A"

   



   
