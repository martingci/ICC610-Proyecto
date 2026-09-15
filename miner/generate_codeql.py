"""
Análisis de Seguridad con CodeQL

Script que automatiza la ejecución de análisis de seguridad estático sobre múltiples
repositorios usando CodeQL CLI, similar a cómo generate_sboms.py automatiza SBOMs.

Proceso:
1. Descubre todos los repositorios en data/repos/
2. Detecta lenguajes presentes en cada repositorio
3. Crea bases de datos de CodeQL (indexa el código)
4. Ejecuta consultas de seguridad predefinidas
5. Convierte SARIF a formato JSON normalizado
6. Guarda resultados en data/results/{repo-name}-codeql.json

Uso:
    python scripts/generate_codeql.py                    # Ejecutar análisis completo
    python scripts/generate_codeql.py --dry-run          # Ver qué se haría sin ejecutar
    python scripts/generate_codeql.py --repos-path PATH  # Con rutas personalizadas

Requisitos:
    - CodeQL CLI instalado (https://github.com/github/codeql-cli-binaries/releases)
    - Query packs descargados: codeql pack download codeql/python-queries codeql/javascript-queries
    - Repositorios clonados en data/repos/

Salida:
    - Archivos JSON en data/results/ con patrón {repo-name}-codeql.json
    - Logs con progreso e información de errores
    - Resumen final con estadísticas de análisis
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


RUTA_BASE_CODEQL = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE_CODEQL / "data" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE_CODEQL / "data" / "results"
SUFIJO_CODEQL = "-codeql.json"
FORMATO_SALIDA_CODEQL = "sarifv2.1.0"
MENSAJE_CODEQL_NO_INSTALADO = (
    "CodeQL CLI is not installed. Please install it from "
    "https://github.com/github/codeql-cli-binaries/releases"
)


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)
PATRON_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class CodeQLAnalyzer:
    def __init__(self, repos_path: str, output_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parents[1]
        self.codeql_bin = "codeql"
        self.dry_run = False
        self.codeql_path: str | None = None
        self.temp_dir: Path | None = None
        self.query_pack_cache = Path.home() / ".codeql" / "query-pack-cache"

    def discover_repositories(self) -> list[str]:
        """Devuelve una lista de rutas de repositorios."""
        self._validar_directorio_repos()

        repositorios = sorted(
            str(ruta.relative_to(self.project_root))
            for ruta in self.repos_path.iterdir()
            if ruta.is_dir()
        )

        if not repositorios:
            LOGGER.warning(
                "No se encontraron repositorios en %s", self.repos_path)

        return repositorios

    def run_codeql(self, repo_path: str, pipeline=False) -> str:
        """Ejecuta CodeQL y devuelve el análisis en formato SARIF JSON."""
        ruta_repo = self.project_root / repo_path

        if not ruta_repo.exists():
            raise FileNotFoundError(f"El repositorio no existe: {ruta_repo}")

        if not ruta_repo.is_dir():
            raise NotADirectoryError(
                f"La ruta no es un directorio: {ruta_repo}")

        if not any(ruta_repo.iterdir()):
            raise ValueError(f"El repositorio esta vacio: {ruta_repo}")

        # Detectar lenguaje por extensiones de archivo
        # (CodeQL falla sin metadatos Git, así que hacemos detección simple)

        if pipeline:
            LOGGER.info(
                f"Pipeline mode: analizando pipeline de {ruta_repo.name}...")
            lenguaje = "actions"  # Forzar lenguaje de queries de GitHub Actions
        else:
            lenguaje = self._detectar_lenguaje_simple(ruta_repo)
            if not lenguaje:
                LOGGER.warning(
                    "No se detectó lenguaje soportado en %s. Se omite.",
                    ruta_repo.name,
                )
                return json.dumps({"runs": []})

            LOGGER.info(f"Lenguaje detectado en {ruta_repo.name}: {lenguaje}")

        # Crear base de datos de CodeQL con lenguaje explícito
        db_path = self._crear_base_datos_codeql(ruta_repo, lenguaje)

        try:
            # Analizar la base de datos
            sarif_output = self._analizar_base_datos_codeql(
                db_path, lenguaje, ruta_repo.name)
            LOGGER.info(f"SARIF output length: {len(sarif_output)} bytes")
            if len(sarif_output) < 200:
                LOGGER.warning(
                    f"SARIF output muy pequeño (probablemente vacío): {sarif_output[:100]}")
            return sarif_output
        finally:
            # Limpiar base de datos temporal
            if db_path.exists():
                shutil.rmtree(db_path, ignore_errors=True)

    def parse_sarif(self, sarif_data: str) -> dict:
        """Convierte SARIF a un formato JSON normalizado."""
        LOGGER.info(f"parse_sarif: recibiendo {len(sarif_data)} bytes")

        try:
            sarif_json = json.loads(sarif_data)
        except json.JSONDecodeError as error:
            LOGGER.error(f"SARIF invalido: {error}")
            raise RuntimeError(f"SARIF invalido: {error}") from error

        # Extraer resultados del formato SARIF
        resultados = {
            "total_issues": 0,
            "issues_by_severity": {"error": 0, "warning": 0, "note": 0},
            "issues": [],
            "sarif_metadata": {
                "version": sarif_json.get("version", "unknown"),
                "schema_uri": sarif_json.get("$schema", ""),
                "tool": self._extraer_tool_metadata(sarif_json),
            },
        }

        # Procesar runs del SARIF
        runs = sarif_json.get("runs", [])
        LOGGER.info(f"parse_sarif: {len(runs)} runs encontrados")

        if runs:
            run = runs[0]  # Típicamente hay un único run
            tool_info = run.get("tool", {}).get("driver", {})
            resultados["sarif_metadata"]["tool_name"] = tool_info.get(
                "name", "codeql")
            resultados["sarif_metadata"]["tool_version"] = tool_info.get(
                "version", "unknown")

            # Procesar resultados individuales
            results_list = run.get("results", [])
            LOGGER.info(
                f"parse_sarif: {len(results_list)} resultados en run[0]")

            for resultado in results_list:
                issue = self._procesar_resultado_sarif(resultado)
                resultados["issues"].append(issue)

                # Contar por severidad
                severidad = resultado.get("level", "warning")
                if severidad in resultados["issues_by_severity"]:
                    resultados["issues_by_severity"][severidad] += 1
                resultados["total_issues"] += 1

        LOGGER.info(f"parse_sarif: total_issues={resultados['total_issues']}")
        return resultados

    def save_analysis(self, repo_name: str, analysis_data: dict, pipeline: bool = False) -> Path:
        """Guarda el análisis en el directorio de salida."""
        if not repo_name:
            raise ValueError("El nombre del repositorio no puede estar vacio.")

        self.output_path.mkdir(parents=True, exist_ok=True)
        if pipeline:
            ruta_salida = self.output_path / f"{repo_name}-pipeline.json"
        else:
            ruta_salida = self.output_path / f"{repo_name}{SUFIJO_CODEQL}"

        LOGGER.info(
            f"save_analysis: {repo_name} con {analysis_data.get('total_issues')} issues")
        contenido_json = json.dumps(
            analysis_data, ensure_ascii=False, indent=2)
        ruta_salida.write_text(contenido_json, encoding="utf-8")
        LOGGER.info("Analisis CodeQL guardado en %s",
                    ruta_salida.relative_to(self.project_root))
        return ruta_salida

    def run(self):
        """Orquesta el descubrimiento y análisis con CodeQL."""
        repositorios = self.discover_repositories()
        self._validar_directorio_salida()

        if not repositorios:
            return

        if not self.dry_run:
            self.codeql_path = self._resolver_codeql()
            LOGGER.info("Usando CodeQL CLI: %s", self.codeql_path)
            # Ejecutar diagnóstico del entorno
            self._diagnosticar_entorno()

        self.output_path.mkdir(parents=True, exist_ok=True)

        repositorios_analizados = 0
        archivos_generados = 0
        omitidos = 0
        errores = 0

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path
            LOGGER.info(
                "[%s/%s] Procesando repositorio %s",
                indice,
                len(repositorios),
                repo_path,
            )

            if self.dry_run:
                if not any(ruta_repo.iterdir()):
                    LOGGER.warning(
                        "[%s/%s] Se omite %s porque esta vacio.",
                        indice,
                        len(repositorios),
                        ruta_repo.name,
                    )
                    omitidos += 1
                    continue

                ruta_salida = self.output_path / \
                    f"{ruta_repo.name}{SUFIJO_CODEQL}"
                LOGGER.info(
                    "[%s/%s] Dry-run: se generaria %s",
                    indice,
                    len(repositorios),
                    ruta_salida.relative_to(self.project_root),
                )
                continue

            try:
                sarif_data = self.run_codeql(repo_path)
                analysis = self.parse_sarif(sarif_data)
                self.save_analysis(ruta_repo.name, analysis)
                repositorios_analizados += 1
                archivos_generados += 1
            except Exception as error:
                errores += 1
                self._eliminar_archivos_parciales(ruta_repo.name)
                LOGGER.error(
                    "[%s/%s] Error al procesar %s: %s",
                    indice,
                    len(repositorios),
                    repo_path,
                    error,
                )

        LOGGER.info(
            "Resumen final | total_repos=%s | repos_analizados=%s | archivos_generados=%s | omitidos=%s | errores=%s",
            len(repositorios),
            repositorios_analizados,
            archivos_generados,
            omitidos,
            errores,
        )

    def run_cicd_analysis(self):
        """Orquesta el descubrimiento y análisis con CodeQL."""
        repositorios = self.discover_repositories()
        self._validar_directorio_salida()

        if not repositorios:
            return

        if not self.dry_run:
            self.codeql_path = self._resolver_codeql()
            LOGGER.info("Usando CodeQL CLI: %s", self.codeql_path)
            # Ejecutar diagnóstico del entorno
            self._diagnosticar_entorno()

        self.output_path.mkdir(parents=True, exist_ok=True)

        repositorios_analizados = 0
        archivos_generados = 0
        omitidos = 0
        errores = 0

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path
            LOGGER.info(
                "[%s/%s] Procesando repositorio %s",
                indice,
                len(repositorios),
                repo_path,
            )

            if self.dry_run:
                if not any(ruta_repo.iterdir()):
                    LOGGER.warning(
                        "[%s/%s] Se omite %s porque esta vacio.",
                        indice,
                        len(repositorios),
                        ruta_repo.name,
                    )
                    omitidos += 1
                    continue

                ruta_salida = self.output_path / \
                    f"{ruta_repo.name}{SUFIJO_CODEQL}"
                LOGGER.info(
                    "[%s/%s] Dry-run: se generaria %s",
                    indice,
                    len(repositorios),
                    ruta_salida.relative_to(self.project_root),
                )
                continue

            try:
                sarif_data = self.run_codeql(repo_path, pipeline=True)
                analysis = self.parse_sarif(sarif_data)
                self.save_analysis(ruta_repo.name, analysis, pipeline=True)
                repositorios_analizados += 1
                archivos_generados += 1
            except Exception as error:
                errores += 1
                self._eliminar_archivos_parciales(ruta_repo.name)
                LOGGER.error(
                    "[%s/%s] Error al procesar %s: %s",
                    indice,
                    len(repositorios),
                    repo_path,
                    error,
                )

        LOGGER.info(
            "Resumen final | total_repos=%s | repos_analizados=%s | archivos_generados=%s | omitidos=%s | errores=%s",
            len(repositorios),
            repositorios_analizados,
            archivos_generados,
            omitidos,
            errores,
        )

    def _validar_directorio_repos(self):
        if not self.repos_path.exists():
            raise FileNotFoundError(
                f"El directorio de repositorios no existe: {self.repos_path}"
            )

        if not self.repos_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de repositorios no es un directorio: {self.repos_path}"
            )

    def _validar_directorio_salida(self):
        if self.output_path.exists() and not self.output_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de salida no es un directorio: {self.output_path}"
            )

    def _resolver_codeql(self) -> str:
        ruta_codeql = shutil.which(self.codeql_bin)
        if not ruta_codeql:
            raise RuntimeError(MENSAJE_CODEQL_NO_INSTALADO)

        return ruta_codeql

    def _diagnosticar_entorno(self):
        """Verifica que las herramientas necesarias estén disponibles."""
        LOGGER.info("=== Diagnóstico del Entorno CodeQL ===")

        # Verificar CodeQL
        try:
            codeql_path = self._resolver_codeql()
            result = subprocess.run(
                [codeql_path, "version"], capture_output=True, text=True, timeout=5)
            version_output = result.stdout.split(
                '\n')[0] if result.stdout else "desconocida"
            LOGGER.info("✓ CodeQL CLI: %s", version_output)
        except Exception as e:
            LOGGER.error("✗ CodeQL CLI: %s", e)
            return False

        # Verificar Node.js (necesario para JavaScript)
        try:
            result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True, timeout=5)
            LOGGER.info("✓ Node.js: %s", result.stdout.strip())
        except FileNotFoundError:
            LOGGER.warning(
                "⚠ Node.js no encontrado (necesario para análisis de JavaScript)")

        # Verificar npm
        try:
            result = subprocess.run(
                ["npm", "--version"], capture_output=True, text=True, timeout=5)
            LOGGER.info("✓ npm: %s", result.stdout.strip())
        except FileNotFoundError:
            LOGGER.warning("⚠ npm no encontrado")

        # Verificar disponibilidad de query packs
        LOGGER.info("Verificando query packs...")
        for lenguaje in ["python", "javascript", "java", "actions"]:
            pack_availble = self._verificar_query_pack(lenguaje)
            if pack_availble:
                LOGGER.info(
                    "✓ Query pack codeql/%s-queries disponible", lenguaje)
            else:
                LOGGER.warning(
                    "⚠ Query pack codeql/%s-queries no disponible", lenguaje)

        LOGGER.info("=== Fin Diagnóstico ===\n")
        return True

    def _verificar_query_pack(self, lenguaje: str) -> bool:
        """Verifica si un query pack está disponible como pack o como suite compilada."""
        try:
            codeql_path = self.codeql_path or self._resolver_codeql()
            # Primero intentar verificar como pack
            result = subprocess.run(
                [codeql_path, "pack", "ls", f"codeql/{lenguaje}-queries"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return True
        except:
            pass

        # Si no está como pack, verificar si existe como suite compilada
        codeql_packages = Path.home() / ".codeql" / "packages" / "codeql"
        suite_pattern = f"{lenguaje}-queries/*/codeql-suites/{lenguaje}-security-and-quality.qls"
        suite_files = list(codeql_packages.glob(suite_pattern))
        return len(suite_files) > 0

    def _descargar_query_pack(self, lenguaje: str) -> bool:
        """Intenta descargar un query pack, con caché local como fallback."""
        try:
            codeql_path = self.codeql_path or self._resolver_codeql()
            LOGGER.info("Descargando query pack para %s...", lenguaje)
            result = subprocess.run(
                [codeql_path, "pack", "download",
                    f"codeql/{lenguaje}-queries"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                LOGGER.info(
                    "✓ Query pack para %s descargado exitosamente", lenguaje)
                return True
            else:
                LOGGER.warning(
                    "⚠ No se pudo descargar query pack para %s: %s", lenguaje, result.stderr[:200])
                return False
        except subprocess.TimeoutExpired:
            LOGGER.warning(
                "⚠ Timeout descargando query pack para %s", lenguaje)
            return False
        except Exception as e:
            LOGGER.warning(
                "⚠ Error descargando query pack para %s: %s", lenguaje, e)
            return False

    def _detectar_lenguaje_simple(self, ruta_repo: Path) -> str | None:
        """Detecta el lenguaje más probable del repositorio por extensiones.

        Estrategia simple:
        - Busca archivos por extensión común
        - Retorna el lenguaje detectado o None si no encuentra nada
        """
        extensiones = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "javascript",
            ".jsx": "javascript",
            ".tsx": "javascript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "cpp",
            ".cs": "csharp",
            ".go": "go",
        }

        conteos = {}
        for archivo in ruta_repo.rglob("*"):
            if archivo.is_file() and archivo.suffix.lower() in extensiones:
                lenguaje = extensiones[archivo.suffix.lower()]
                conteos[lenguaje] = conteos.get(lenguaje, 0) + 1

        if not conteos:
            return None

        # Retorna el lenguaje más frecuente
        return max(conteos, key=conteos.get)

    def _crear_base_datos_codeql(self, ruta_repo: Path, lenguaje: str) -> Path:
        """Crea una base de datos de CodeQL para el repositorio.

        Usa el lenguaje detectado explícitamente por _detectar_lenguaje_simple.
        Si autobuild falla para JavaScript, intenta con --skip-autobuild como fallback.
        """
        if self.temp_dir is None:
            # Usar tempfile.gettempdir() es portable entre Windows y Linux
            self.temp_dir = Path(tempfile.gettempdir()) / "codeql_analysis"
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            LOGGER.info(f"Directorio temporal CodeQL: {self.temp_dir}")

        db_path = self.temp_dir / f"{ruta_repo.name}_db"

        codeql_path = self.codeql_path or self._resolver_codeql()
        # Con --language explícito (detección manual por extensiones)
        comando = [
            codeql_path,
            "database",
            "create",
            str(db_path),
            "--language",
            lenguaje,
            "--source-root",
            str(ruta_repo),
            "--overwrite",  # Permitir sobrescribir DBs existentes
            "--ram=4096"
        ]

        LOGGER.info(
            "Creando base de datos CodeQL para %s (lenguaje: %s)...", ruta_repo.name, lenguaje)
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=False,
        )

        # Si falla y es JavaScript, intentar con --skip-autobuild como fallback
        if resultado.returncode != 0 and lenguaje == "javascript":
            LOGGER.warning(
                "Autobuild falló para %s. Intentando con --skip-autobuild...", ruta_repo.name)

            db_path_retry = self.temp_dir / f"{ruta_repo.name}_db_noautobuild"
            comando_retry = [
                codeql_path,
                "database",
                "create",
                str(db_path_retry),
                "--language",
                lenguaje,
                "--source-root",
                str(ruta_repo),
                "--overwrite",
                "--skip-autobuild",  # Fallback: sin compile automático
                "--ram=4096"
            ]

            resultado_retry = subprocess.run(
                comando_retry,
                capture_output=True,
                text=True,
                check=False,
            )

            if resultado_retry.returncode == 0:
                LOGGER.info(
                    "✓ Base de datos creada exitosamente con --skip-autobuild")
                return db_path_retry
            else:
                # Ambos intentos fallaron
                detalle_error = resultado_retry.stderr.strip(
                ) or "CodeQL termino con un error desconocido."
                raise RuntimeError(
                    f"No fue posible crear la base de datos CodeQL para {ruta_repo.name} (intentos con y sin autobuild): {detalle_error}"
                )

        # Para otros lenguajes o si el primer intento de JS funcionó
        if resultado.returncode != 0:
            detalle_error = resultado.stderr.strip() or "CodeQL termino con un error desconocido."
            raise RuntimeError(
                f"No fue posible crear la base de datos CodeQL para {ruta_repo.name}: {detalle_error}"
            )

        return db_path

    def _resolver_query_suite(self, lenguaje: str) -> str:
        """Resuelve la suite de queries para el lenguaje específico.

        Estrategia:
        1. Verificar si el query pack está disponible
        2. Si no, intentar descargarlo
        3. Fallback a query pack directo como último recurso
        """
        codeql_packages = Path.home() / ".codeql" / "packages" / "codeql"

        # Buscar suite explícita compilada
        suite_pattern = f"{lenguaje}-queries/*/codeql-suites/{lenguaje}-security-and-quality.qls"
        suite_files = list(codeql_packages.glob(suite_pattern))

        if suite_files:
            query_suite = str(suite_files[0])
            LOGGER.info(f"Usando suite compilada: {query_suite}")
            return query_suite

        # Verificar si el query pack está disponible, si no intentar descargarlo
        query_suite = f"codeql/{lenguaje}-queries"
        if not self._verificar_query_pack(lenguaje):
            LOGGER.info(
                f"Query pack {query_suite} no disponible. Intentando descargar...")
            self._descargar_query_pack(lenguaje)

        # Usar query pack directo (funciona para todos los lenguajes)
        LOGGER.info(f"Usando query pack: {query_suite}")
        return query_suite

    def _analizar_base_datos_codeql(self, db_path: Path, lenguaje: str, repo_name: str) -> str:
        """Analiza la base de datos de CodeQL y devuelve SARIF."""
        codeql_path = self.codeql_path or self._resolver_codeql()

        # Resolver la suite de seguridad para el lenguaje detectado
        query_suite = self._resolver_query_suite(lenguaje)

        # Guardar SARIF directamente en el directorio de resultados (no en temp)
        # Esto evita problemas de sincronización y facilita debugging
        self.output_path.mkdir(parents=True, exist_ok=True)
        sarif_output = self.output_path / f"{repo_name}_temp.sarif"

        comando = [
            codeql_path,
            "database",
            "analyze",
            str(db_path),
            query_suite,  # Usar la suite completa
            f"--format={FORMATO_SALIDA_CODEQL}",
            # Guardar en archivo del output directory
            f"--output={str(sarif_output)}",
            "--ram=6000",
            "--threads=2"
        ]

        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=False,
        )

        if resultado.returncode != 0:
            # Log del error pero continuar
            stderr_msg = resultado.stderr.strip() if resultado.stderr else "Sin detalles en stderr"
            stdout_msg = resultado.stdout.strip() if resultado.stdout else ""

            # Detectar error específico de query pack no encontrado
            if "cannot be found" in stderr_msg or "not found" in stderr_msg:
                LOGGER.warning(
                    "Query pack '%s' no encontrado. Esto puede ocurrir si los query packs no están instalados. "
                    "Intenta: codeql pack download codeql/%s-queries",
                    query_suite, lenguaje
                )

            error_context = f"\n  Comando: {' '.join(comando)}\n"
            error_context += f"  Código de error: {resultado.returncode}\n"
            error_context += f"  STDERR: {stderr_msg}\n"
            if stdout_msg:
                # Primeros 500 chars de stdout
                error_context += f"  STDOUT: {stdout_msg[:500]}\n"
            error_context += f"  Base de datos: {db_path}\n"
            error_context += f"  Suite de queries: {query_suite}\n"
            error_context += f"  Archivo de salida esperado: {sarif_output}\n"
            error_context += "  Nota: Si el archivo SARIF existe, se intentará procesarlo igualmente"

            LOGGER.warning(
                "CodeQL devolvió un código de error:%s", error_context)

        # Leer el archivo SARIF generado
        if sarif_output.exists():
            salida = sarif_output.read_text(encoding="utf-8")
            # MANTENER el archivo temporal para debugging
            LOGGER.info(
                f"SARIF guardado en: {sarif_output} ({len(salida)} bytes)")
            # NO eliminar - dejar para debugging
            return salida
        else:
            # Si no hay archivo, devolver SARIF vacío
            LOGGER.warning(
                "Archivo SARIF no fue generado para %s", db_path.name)
            return json.dumps({"version": "2.1.0", "runs": []})

    def _normalizar_sarif(self, salida_cruda: str) -> str:
        """Limpia y valida el SARIF JSON."""
        if not salida_cruda or not salida_cruda.strip():
            return ""

        texto_limpio = PATRON_ANSI.sub(
            "", salida_cruda).replace("\ufeff", "").strip()

        # Intentar extraer SARIF como objeto JSON
        candidatos = [texto_limpio]

        inicio_objeto = texto_limpio.find("{")
        fin_objeto = texto_limpio.rfind("}")
        if inicio_objeto != -1 and fin_objeto != -1 and inicio_objeto < fin_objeto:
            candidatos.append(texto_limpio[inicio_objeto: fin_objeto + 1])

        for candidato in candidatos:
            try:
                contenido = json.loads(candidato)
                return json.dumps(contenido, ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                continue

        return ""

    def _procesar_resultado_sarif(self, resultado: dict) -> dict:
        """Convierte un resultado individual del SARIF a formato normalizado."""
        message = resultado.get("message", {})
        locations = resultado.get("locations", [])
        location = locations[0] if locations else {}
        physical_location = location.get("physicalLocation", {})
        artifact = physical_location.get("artifactLocation", {})

        issue = {
            "rule_id": resultado.get("ruleId", "unknown"),
            "rule_index": resultado.get("ruleIndex", -1),
            "level": resultado.get("level", "warning"),
            "message": message.get("text", "") if isinstance(message, dict) else str(message),
            "file": artifact.get("uri", "unknown"),
            "region": physical_location.get("region", {}),
            "kind": resultado.get("kind", "notApplicable"),
            "properties": resultado.get("properties", {}),
        }

        return issue

    def _extraer_tool_metadata(self, sarif_json: dict) -> dict:
        """Extrae metadatos de la herramienta del SARIF."""
        runs = sarif_json.get("runs", [])
        if runs:
            tool = runs[0].get("tool", {}).get("driver", {})
            return {
                "name": tool.get("name", "unknown"),
                "version": tool.get("version", "unknown"),
                "information_uri": tool.get("informationUri", ""),
            }
        return {"name": "unknown", "version": "unknown", "information_uri": ""}

    def _eliminar_archivos_parciales(self, repo_name: str):
        ruta_salida = self.output_path / f"{repo_name}{SUFIJO_CODEQL}"
        if ruta_salida.exists():
            ruta_salida.unlink()


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Genera análisis CodeQL en JSON para todos los repositorios."
    )
    parser.add_argument(
        "--repos-path",
        default=str(RUTA_REPOS_POR_DEFECTO),
        help="Ruta al directorio que contiene los repositorios a analizar.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Ruta al directorio donde se guardaran los analisis CodeQL.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra que repositorios se procesarian sin ejecutar CodeQL.",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Ejecuta un diagnóstico del entorno sin analizar repositorios.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    analizador = CodeQLAnalyzer(args.repos_path, args.output_path)
    analizador.dry_run = args.dry_run

    try:
        # Si se solicita diagnóstico, solo ejecutar eso
        if args.diagnose:
            LOGGER.info("Ejecutando diagnóstico del entorno CodeQL...")
            analizador.codeql_path = analizador._resolver_codeql()
            analizador._diagnosticar_entorno()
            return 0

        analizador.run()
    except Exception as error:
        LOGGER.error("%s", error)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
