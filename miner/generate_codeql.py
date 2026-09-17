"""
Análisis de Seguridad con CodeQL

Script que automatiza la ejecución de análisis de seguridad estático sobre múltiples
repositorios usando CodeQL CLI.

Proceso:
1. Descubre todos los repositorios en miner/repos/
2. Detecta lenguajes presentes en cada repositorio
3. Crea bases de datos de CodeQL con `database create` (indexa el código)
4. Ejecuta las consultas de seguridad predefinidas con `database analyze`
5. CodeQL entrega los resultados en formato SARIF (archivo temporal de depuración)
6. Convierte el SARIF a un formato JSON normalizado (entrega final)

Uso:
    python3 miner/generate_codeql.py --repos-path miner/repos --output-path results
    python3 miner/generate_codeql.py --diagnose

Requisitos:
    - CodeQL CLI instalado (https://github.com/github/codeql-cli-binaries/releases)
    - Query packs descargados: codeql pack download codeql/{python,javascript,java,actions}-queries
    - Repositorios clonados en miner/repos/

Salida:
    - {repo}-codeql.json: Análisis normalizado de código fuente
    - {repo}-pipeline.json: Análisis normalizado de pipelines CI
    - {repo}_temp.sarif / {repo}_pipeline_temp.sarif: SARIF crudo (depuración)
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path


RUTA_BASE_CODEQL = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE_CODEQL / "miner" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE_CODEQL / "results"
SUFIJO_CODIGO = "-codeql.json"
SUFIJO_PIPELINE = "-pipeline.json"
SUFIJO_SARIF = "_temp.sarif"
SUFIJO_SARIF_PIPELINE = "_pipeline_temp.sarif"
FORMATO_SALIDA_CODEQL = "sarifv2.1.0"
SARIF_VACIO = json.dumps({"version": "2.1.0", "runs": []})
MENSAJE_CODEQL_NO_INSTALADO = (
    "CodeQL CLI no está instalado. Instálalo desde "
    "https://github.com/github/codeql-cli-binaries/releases"
)
LENGUAJES_POR_EXTENSION = {
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


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


class CodeQLAnalyzer:
    def __init__(self, repos_path: str, output_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parents[1]
        self.codeql_bin = "codeql"
        self.codeql_path: str | None = None
        self._temp_dir: Path | None = None

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

    def run(self, pipeline: bool = False):
        """Analiza todos los repositorios con CodeQL (código fuente o pipeline CI)."""
        repositorios = self.discover_repositories()
        if not repositorios:
            return

        self._validar_directorio_salida()
        self.output_path.mkdir(parents=True, exist_ok=True)

        self.codeql_path = self._resolver_codeql()
        self._diagnosticar_entorno()

        modo = "pipeline CI" if pipeline else "código fuente"
        analizados = archivos = errores = omitidos = 0

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path

            if pipeline and not self._tiene_flujo_ci(ruta_repo):
                omitidos += 1
                LOGGER.info(
                    "[%s/%s] %s sin flujo CI (.github/workflows). Se omite.",
                    indice, len(repositorios), repo_path,
                )
                continue

            LOGGER.info(
                "[%s/%s] Procesando %s (%s)",
                indice, len(repositorios), repo_path, modo,
            )

            try:
                sarif_data = self.run_codeql(repo_path, pipeline=pipeline)
                analysis = self.parse_sarif(sarif_data)
                self.save_analysis(ruta_repo.name, analysis, pipeline=pipeline)
                analizados += 1
                archivos += 1
            except Exception as error:
                errores += 1
                self._eliminar_archivos_parciales(ruta_repo.name)
                LOGGER.error(
                    "[%s/%s] Error al procesar %s: %s",
                    indice, len(repositorios), repo_path, error,
                )

        if pipeline:
            LOGGER.info(
                "Resumen final (pipeline CI) | total_repos=%s | "
                "repos_analizados=%s | archivos_generados=%s | omitidos=%s | "
                "errores=%s",
                len(repositorios), analizados, archivos, omitidos, errores,
            )
        else:
            LOGGER.info(
                "Resumen final (código fuente) | total_repos=%s | "
                "repos_analizados=%s | archivos_generados=%s | errores=%s",
                len(repositorios), analizados, archivos, errores,
            )

    def run_cicd_analysis(self):
        """Analiza los pipelines CI de todos los repositorios con CodeQL."""
        return self.run(pipeline=True)

    def _tiene_flujo_ci(self, ruta_repo: Path) -> bool:
        """Verifica que el repositorio defina flujos de CI en GitHub Actions."""
        return (ruta_repo / ".github" / "workflows").is_dir()

    def run_codeql(self, repo_path: str, pipeline: bool = False) -> str:
        """Ejecuta CodeQL y devuelve el análisis en formato SARIF JSON."""
        ruta_repo = self.project_root / repo_path
        self._validar_repositorio(ruta_repo)

        lenguaje = "actions" if pipeline else self._detectar_lenguaje_simple(
            ruta_repo)
        if not lenguaje:
            LOGGER.warning(
                "No se detectó lenguaje soportado en %s. Se omite.", ruta_repo.name
            )
            return SARIF_VACIO
        LOGGER.info("Lenguaje detectado en %s: %s", ruta_repo.name, lenguaje)

        db_path = self._crear_base_datos_codeql(ruta_repo, lenguaje)
        try:
            sarif_output = self._analizar_base_datos_codeql(
                db_path, lenguaje, ruta_repo.name,
                SUFIJO_SARIF_PIPELINE if pipeline else SUFIJO_SARIF)
            if len(sarif_output) < 200:
                LOGGER.warning(
                    "SARIF output muy pequeño (probablemente vacío): %s",
                    sarif_output[:100],
                )
            return sarif_output
        finally:
            # Limpiar base de datos temporal
            if db_path.exists():
                shutil.rmtree(db_path, ignore_errors=True)

    def _crear_base_datos_codeql(self, ruta_repo: Path, lenguaje: str) -> Path:
        """Crea la base de datos de CodeQL, reintentando sin autobuild en JS."""
        try:
            return self._crear_db(ruta_repo, lenguaje)
        except RuntimeError as primer_error:
            if lenguaje != "javascript":
                raise
            LOGGER.warning(
                "Autobuild falló para %s. Reintentando con --skip-autobuild...",
                ruta_repo.name,
            )
            try:
                return self._crear_db(ruta_repo, lenguaje, skip_autobuild=True)
            except RuntimeError as segundo_error:
                raise RuntimeError(
                    f"No fue posible crear la base de datos CodeQL para "
                    f"{ruta_repo.name} (intentos con y sin autobuild): "
                    f"{primer_error} | {segundo_error}"
                ) from segundo_error

    def _crear_db(
        self, ruta_repo: Path, lenguaje: str, skip_autobuild: bool = False
    ) -> Path:
        codeql_path = self.codeql_path or self._resolver_codeql()
        sufijo = "_noautobuild" if skip_autobuild else ""
        db_path = self._directorio_temporal() / f"{ruta_repo.name}_db{sufijo}"

        comando = [
            codeql_path, "database", "create",
            str(db_path),
            "--language", lenguaje,
            "--source-root", str(ruta_repo),
            "--overwrite",
            "--ram=4096",
        ]
        if skip_autobuild:
            comando.append("--skip-autobuild")

        LOGGER.info(
            "Creando base de datos CodeQL para %s (lenguaje: %s)...",
            ruta_repo.name, lenguaje,
        )
        resultado = subprocess.run(
            comando, capture_output=True, text=True, check=False)
        if resultado.returncode != 0:
            detalle = resultado.stderr.strip() or "CodeQL terminó con un error desconocido."
            raise RuntimeError(
                f"No fue posible crear la base de datos CodeQL para {ruta_repo.name}: {detalle}"
            )
        return db_path

    def _analizar_base_datos_codeql(
        self, db_path: Path, lenguaje: str, repo_name: str,
        sufijo_sarif: str = SUFIJO_SARIF,
    ) -> str:
        """Analiza la base de datos con el query pack de seguridad y devuelve SARIF."""
        codeql_path = self.codeql_path or self._resolver_codeql()
        query_suite = self._resolver_query_suite(lenguaje)

        # Guardar el SARIF en el directorio de resultados (para depuración)
        self.output_path.mkdir(parents=True, exist_ok=True)
        sarif_output = self.output_path / f"{repo_name}{sufijo_sarif}"

        comando = [
            codeql_path, "database", "analyze",
            str(db_path),
            query_suite,
            f"--format={FORMATO_SALIDA_CODEQL}",
            f"--output={str(sarif_output)}",
            "--ram=6000",
            "--threads=6",
        ]

        resultado = subprocess.run(
            comando, capture_output=True, text=True, check=False)
        if resultado.returncode != 0:
            detalle = resultado.stderr.strip() or resultado.stdout.strip() or "Sin detalles"
            LOGGER.warning(
                "CodeQL devolvió un código de error para %s (query pack '%s'): %s",
                repo_name, query_suite, detalle,
            )

        if sarif_output.exists():
            LOGGER.info(
                "SARIF guardado en: %s (%s bytes)",
                sarif_output.relative_to(self.project_root),
                sarif_output.stat().st_size,
            )
            return sarif_output.read_text(encoding="utf-8")

        LOGGER.warning("Archivo SARIF no fue generado para %s", repo_name)
        return SARIF_VACIO

    def _resolver_query_suite(self, lenguaje: str) -> str:
        """Resuelve el query pack de seguridad para el lenguaje.

        Prioriza la suite compilada `{lenguaje}-security-and-quality.qls` cuando
        está disponible en el caché (esto mantiene los mismos resultados que los
        resultados históricos) y en su defecto usa el query pack oficial de CodeQL.
        """
        suite_compilada = self._buscar_suite_compilada(lenguaje)
        if suite_compilada:
            return suite_compilada

        query_suite = f"codeql/{lenguaje}-queries"
        if not self._verificar_query_pack(lenguaje):
            raise RuntimeError(
                f"Query pack '{query_suite}' no disponible. "
                f"Ejecuta: codeql pack download {query_suite}"
            )
        return query_suite

    def _buscar_suite_compilada(self, lenguaje: str) -> str | None:
        """Busca la suite de seguridad y calidad compilada en el caché de CodeQL."""
        codeql_packages = Path.home() / ".codeql" / "packages" / "codeql"
        patron = (
            f"{lenguaje}-queries/*/codeql-suites/"
            f"{lenguaje}-security-and-quality.qls"
        )
        suites = list(codeql_packages.glob(patron))
        if suites:
            LOGGER.info("Usando suite compilada: %s", suites[0])
            return str(suites[0])
        return None

    def _verificar_query_pack(self, lenguaje: str) -> bool:
        """Verifica que el query pack esté descargado en el caché de CodeQL."""
        paquete = Path.home() / ".codeql" / "packages" / \
            "codeql" / f"{lenguaje}-queries"
        return paquete.is_dir()

    def parse_sarif(self, sarif_data: str) -> dict:
        """Convierte SARIF a un formato JSON normalizado."""
        try:
            sarif_json = json.loads(sarif_data)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"SARIF inválido: {error}") from error

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

        runs = sarif_json.get("runs", [])
        if runs:
            tool_info = runs[0].get("tool", {}).get("driver", {})
            resultados["sarif_metadata"]["tool_name"] = tool_info.get(
                "name", "codeql")
            resultados["sarif_metadata"]["tool_version"] = tool_info.get(
                "version", "unknown")

            for resultado in runs[0].get("results", []):
                resultados["issues"].append(
                    self._procesar_resultado_sarif(resultado))
                severidad = resultado.get("level", "warning")
                if severidad in resultados["issues_by_severity"]:
                    resultados["issues_by_severity"][severidad] += 1
                resultados["total_issues"] += 1

        LOGGER.info("parse_sarif: total_issues=%s", resultados["total_issues"])
        return resultados

    def _procesar_resultado_sarif(self, resultado: dict) -> dict:
        """Convierte un resultado individual del SARIF a formato normalizado."""
        message = resultado.get("message", {})
        locations = resultado.get("locations", [])
        location = locations[0] if locations else {}
        physical_location = location.get("physicalLocation", {})
        artifact = physical_location.get("artifactLocation", {})

        return {
            "rule_id": resultado.get("ruleId", "unknown"),
            "rule_index": resultado.get("ruleIndex", -1),
            "level": resultado.get("level", "warning"),
            "message": message.get("text", "") if isinstance(message, dict) else str(message),
            "file": artifact.get("uri", "unknown"),
            "region": physical_location.get("region", {}),
            "kind": resultado.get("kind", "notApplicable"),
            "properties": resultado.get("properties", {}),
        }

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

    def save_analysis(
        self, repo_name: str, analysis_data: dict, pipeline: bool = False
    ) -> Path:
        """Guarda el análisis normalizado en el directorio de salida."""
        if not repo_name:
            raise ValueError("El nombre del repositorio no puede estar vacío.")

        self.output_path.mkdir(parents=True, exist_ok=True)
        sufijo = SUFIJO_PIPELINE if pipeline else SUFIJO_CODIGO
        ruta_salida = self.output_path / f"{repo_name}{sufijo}"
        ruta_salida.write_text(
            json.dumps(analysis_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        LOGGER.info(
            "Análisis CodeQL guardado en %s (total_issues=%s)",
            ruta_salida.relative_to(self.project_root),
            analysis_data.get("total_issues"),
        )
        return ruta_salida

    def _detectar_lenguaje_simple(self, ruta_repo: Path) -> str | None:
        """Detecta el lenguaje más probable del repositorio por extensiones."""
        conteos: dict[str, int] = {}
        for archivo in ruta_repo.rglob("*"):
            if archivo.is_file() and archivo.suffix.lower() in LENGUAJES_POR_EXTENSION:
                lenguaje = LENGUAJES_POR_EXTENSION[archivo.suffix.lower()]
                conteos[lenguaje] = conteos.get(lenguaje, 0) + 1

        if not conteos:
            return None
        return max(conteos, key=conteos.get)

    def _directorio_temporal(self) -> Path:
        if self._temp_dir is None:
            self._temp_dir = Path(tempfile.gettempdir()) / "codeql_analysis"
            self._temp_dir.mkdir(parents=True, exist_ok=True)
            LOGGER.info("Directorio temporal CodeQL: %s", self._temp_dir)
        return self._temp_dir

    def _validar_repositorio(self, ruta_repo: Path):
        if not ruta_repo.exists():
            raise FileNotFoundError(f"El repositorio no existe: {ruta_repo}")
        if not ruta_repo.is_dir():
            raise NotADirectoryError(
                f"La ruta no es un directorio: {ruta_repo}")
        if not any(ruta_repo.iterdir()):
            raise ValueError(f"El repositorio está vacío: {ruta_repo}")

    def _validar_directorio_repos(self):
        if not self.repos_path.exists():
            raise FileNotFoundError(
                f"El directorio de repositorios no existe: {self.repos_path}")
        if not self.repos_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de repositorios no es un directorio: {self.repos_path}")

    def _validar_directorio_salida(self):
        if self.output_path.exists() and not self.output_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de salida no es un directorio: {self.output_path}")

    def _resolver_codeql(self) -> str:
        ruta_codeql = shutil.which(self.codeql_bin)
        if not ruta_codeql:
            raise RuntimeError(MENSAJE_CODEQL_NO_INSTALADO)
        return ruta_codeql

    def _diagnosticar_entorno(self):
        """Verifica que las herramientas necesarias estén disponibles."""
        LOGGER.info("=== Diagnóstico del Entorno CodeQL ===")

        codeql_path = self._resolver_codeql()
        try:
            resultado = subprocess.run(
                [codeql_path, "version"], capture_output=True, text=True, timeout=5)
            version = resultado.stdout.split(
                "\n")[0] if resultado.stdout else "desconocida"
            LOGGER.info("✓ CodeQL CLI: %s", version)
        except Exception as e:
            LOGGER.error("✗ CodeQL CLI: %s", e)
            return False

        # Node.js y npm (necesarios para análisis de JavaScript)
        for comando, nombre in [(["node", "--version"], "Node.js"),
                                (["npm", "--version"], "npm")]:
            try:
                resultado = subprocess.run(
                    comando, capture_output=True, text=True, timeout=5)
                LOGGER.info("✓ %s: %s", nombre, resultado.stdout.strip())
            except FileNotFoundError:
                LOGGER.warning("⚠ %s no encontrado", nombre)

        LOGGER.info("Verificando query packs...")
        for lenguaje in ["python", "javascript", "java", "actions"]:
            if self._verificar_query_pack(lenguaje):
                LOGGER.info(
                    "✓ Query pack codeql/%s-queries disponible", lenguaje)
            else:
                LOGGER.warning(
                    "⚠ Query pack codeql/%s-queries no disponible", lenguaje)

        LOGGER.info("=== Fin Diagnóstico ===\n")
        return True

    def _eliminar_archivos_parciales(self, repo_name: str):
        for sufijo in [SUFIJO_CODIGO, SUFIJO_PIPELINE]:
            ruta = self.output_path / f"{repo_name}{sufijo}"
            if ruta.exists():
                ruta.unlink()


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
        help="Ruta al directorio donde se guardarán los análisis CodeQL.",
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

    try:
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
