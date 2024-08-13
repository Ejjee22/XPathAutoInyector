# XPathAutoInyector
Script creado para automatizar la explotación de una vulnerabilidad XPath Inyection. Esta concebido para resolver el apartado de dicha vulnerabilidad del CTF [XNMA 1](https://www.vulnhub.com/entry/xtreme-vulnerable-web-application-xvwa-1,209/). Este script en Python es una evolución del que el profesor Marcelo Vázquez aka S4vitar utiliza en la clase correspondiente a esta vulnerabilidad en el curso de `Introducción al Hacking` de su academia [Hack4u](https://hack4u.io/cursos/introduccion-al-hacking/); pensada para obtener de forma automática todo el documento XML que hay detrás de un XPath vulnerable a este tipo de inyecciones.

## Requisitos
- Python3
- Librería pwntools

## Uso en otras máquinas
Es posible modificar este script para hacerlo funcionar en otros entornos que previamente hayamos comprobado que son vulnerables. Para ello, necesitaremos cambiar la variable global `main_url` así como la función `xPathInyect()` para que el contenido que se busque en la respuesta concuerde con el escenario al que nos enfrentamos.
