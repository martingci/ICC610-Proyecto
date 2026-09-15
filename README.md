# Proyecto de ciberseguridad:

## Estudiantes:
- David Baez.
- Martín Carrasco.
- Sabrina López.

## Ejecución

1. Cargar _devcontainer_ (automático).
2. Ejecutar el miner desde el cuaderno miner/run_miner.ipynb o ejecutar el siguiente código:

``` bash

python3 miner/main.py

```

3. Posteriormente ejecutar el cuarderno analyzer/analyzer.ipynb y así generar la información utilizada en el _visualizer_.
4. Finalmente para le ejecución del _visualizer_ se ejecuta desde la carpeta raíz

```bash
python3 -m http.server 8000
```

Luego, abrir en navegador: `http://localhost:8000/visualizer/`

## Arquitectura

La arquitectura de la solución realizada se centra en los 3 componentes principales.
1. **Miner:** Encargado de obtener los repositorios a través de la API de Github, obtener el SBOM con Syft, ejecutar el análisis estático del código fuente de CodeQL y del CI, y las vulnerabilidades de los componentes con Grype. Para cada uno de estos elementos se realizó un objeto encargado de ejecutar cada una de las acciones, y se orquestó por medio de un archivo _run_miner.ipynb_ que define los directorios de almacenamiento de repositorios y donde se guarda la información. 
2. **Analyzer:** Encargado de analizar la información obtenida del _miner_, donde crea diferentes _DataFrames_ por cada conjunto de datos (_SBOMs_, código fuente, vulnerabilidades de dependencias, y CI), y en base a su información crea gráficos junto a un análisis. Posteriormente guarda la información utilizada para graficar en _results/categoría_. 
3. **Visualizer:** Muestra la información obtenida a través del _analyzer_ a través de un archivo _html_, el cual utiliza la biblioteca de _D3_, que permite realizar gráficos con _JavaScript_.

## Contextualización

En diciembre del año pasado, 2025, [se detectaron varias vulnerabilidades en los componentes de React Server](https://vercel.com/kb/bulletin/react2shell) que utiliza Vercel, cuyas calificaciones de CVSS van desde 7,5 a 10. Tales grados de gravedad generan una gran preocupación por la seguridad de sus usuarios, ya que, Vercel proporciona herramientas para desarrolladores e infraestructura en la nube para diversos proyectos de software de distintas áreas, muchos de los cuales también ofrecen servicios gratuitos en la web a otros usuarios que también pueden verse comprometidos por estas vulnerabilidades.

Es por esto que el análisis realizado busca comprobar si existen otras vulnerabilidades por descubrir dentro de los componentes de la organización. Para esto se realizaron los SBOMs, análisis estático del código fuente con CodeQL, y análisis de vulnerabilidades con Grype de los 25 repositorios de libre acceso más populares (con más estrellas) de Vercel.

## Resultados cuantitativos

Las cifras totales obtenidas se componen de:
- 6470 problemas de código fuente, todos de nivel de severidad *“warning”*, es decir, medio dentro de la clasificación de SARIF.
- 17074 vulnerabilidades de componentes, todas de nivel de severidad *“low”*, es decir, bajo dentro de la clasificación CVSS.
- 206 problemas en los procesos de CI, principalmente el repo **next.js**.

## Análisis cualificativo

Aparte de los problemas y vulnerabilidades más recurrentes entre los repositorios que fueron analizados dentro del [notebook](analyzer/analyzer.ipynb), al equipo le llamó la atención las vulnerabilidades del componente Kysely dentro de los repositorio de *chatbot* y *examples*, que contenían dos amenazas de posibles inyecciones SQL calificadas con un CVSS de [8,1](https://github.com/advisories/GHSA-8cpq-38p9-67gx) y de [8,2](https://github.com/advisories/GHSA-wmrf-hv6w-mr66), con Vercel aún manteniendo la versión afectada por ambas, a pesar de que la primera ya ha sido corregida en la versión 0.28.14 y la segunda fue corregida en la versión 0.28.12.

Dentro del análisis de vulnerabilidades, las de dependencias sólo se clasifican como “low”, es decir, por debajo de 3,9, sin embargo, las comprobaciones manuales del equipo muestran que varias vulnerabilidades en realidad tienen niveles de severidad distintos a los vistos, evidenciando que la utilización de diferentes herramientas entrega resultados distintos, por lo que, ahí es donde entra el trabajo del equipo de revisar estas contradicciones y registrarlas para mejorar los análisis posteriores.

Luego de la comprobación realizada, se encontró que el error era que la información de los archivos tenían un formato nuevo, por lo que los datos de nivel de severidad habían cambiado la forma de guardarse. Por lo tanto, el conteo final (y correcto) de vulnerabilidades de dependencias fue de:
- 1858 de nivel "low" (0 a 3,9)
- 7847 de nivel "medium" (4 a 6,9)
- 6532 de nivel "high" (7 a 8,9)
- 837 de nivel "critical" (9 a 10)

La distribución del nivel de severidad de las vulnerabilidades de dependencias es altamente preocupante, ya que, si bien la mayor cantidad se encuentra en "medium", el rango numérico de la severidad "high" es menor. Esto indica un riesgo muy grande para la organización, aumentando su probabilidad de ser víctimas (nuevamente) de un ciberataque debido al peligro que presenta que un atacante pueda aprovecharse de esto.

## Conclusiones

Para finalizar, se comprobó que la organización Vercel todavía presenta muchas vulnerabilidades y de altas severidades en sus dependencias utilizadas, sin embargo, el equipo investigó y Vercel se toma en serio estas advertencias y, al ser informado de estas amenazas, probablemente tomará medidas de protección a sus usuarios, como ocurrió en el caso de diciembre de 2025 y como lo hace en sus blogs públicos sobre los avances de prevención y seguridad.

Por el lado del trabajo de análisis realizado, el equipo comprueba la importancia de revisar los resultados obtenidos, problemas de código fuente, y vulnerabilidades de las dependencias para contrastar las posibles contradicciones con los registros públicos disponibles. Con esta buena práctica, se puede tener más seguridad sobre la calidad de la información y del trabajo realizado.
