"""
Análisis de Vulnerabilidades con Grype

Script que automatiza el escaneo de vulnerabilidades en dependencias sobre múltiples
repositorios usando Grype, una herramienta de análisis de seguridad enfocada en
Software Component Analysis (SCA).

Proceso:
1. Descubre todos los repositorios en miner/repos/
2. Escanea cada repositorio buscando manifests de dependencias
3. Ejecuta Grype para detectar vulnerabilidades conocidas
4. Normaliza la salida JSON de Grype
5. Guarda resultados en results/ con dos formatos:
   - {repo}-grype-raw.json: Salida original de Grype (para depuración)
   - {repo}-grype.json: Formato normalizado (para análisis)

Uso:
    python3 miner/generate_grype.py --repos-path miner/repos --output-path results
    python3 miner/generate_grype.py --diagnose

Requisitos:
    - Grype CLI instalado (https://github.com/anchore/grype)
    - Grype DB actualizada (se descarga automáticamente en primer uso)
    - Repositorios clonados en miner/repos/

Salida:
    - {repo}-grype-raw.json: Salida original de Grype
    - {repo}-grype.json: Formato normalizado
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from pathlib import Path


RUTA_BASE_GRYPE = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE_GRYPE / "miner" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE_GRYPE / "results"
SUFIJO_GRYPE_RAW = "-grype-raw.json"
SUFIJO_GRYPE = "-grype.json"
FORMATO_SALIDA_GRYPE = "json"
MENSAJE_GRYPE_NO_INSTALADO = (
    "Grype CLI no está instalado. Instálalo desde "
    "https://github.com/anchore/grype"
)
MANIFESTS_SOPORTADOS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "poetry.lock": "poetry",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
}


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


class GrypeAnalyzer:
    """Analizador de vulnerabilidades en dependencias usando Grype."""

    def __init__(self, repos_path: str, output_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parents[1]
        self.grype_bin = "grype"
        self.grype_path: str | None = None
        self._archivos_generados: list[Path] = []

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

    def run(self):
        """Orquesta el descubrimiento y análisis con Grype."""
        repositorios = self.discover_repositories()
        if not repositorios:
            LOGGER.warning("No se encontraron repositorios. Saliendo.")
            return

        self._validar_directorio_salida()
        self.output_path.mkdir(parents=True, exist_ok=True)

        self._diagnosticar_entorno()

        contadores = {"analizados": 0, "archivos": 0, "errores": 0}

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path

            LOGGER.info(
                "[%s/%s] Escaneando %s con Grype...",
                indice, len(repositorios), repo_path,
            )

            try:
                grype_output = self.run_grype(repo_path)
                analysis = self.parse_grype_output(grype_output)
                self.save_analysis(ruta_repo.name, grype_output, analysis)
                contadores["analizados"] += 1
                contadores["archivos"] += 2  # raw + normalizado
            except Exception as error:
                contadores["errores"] += 1
                self._eliminar_archivos_parciales(ruta_repo.name)
                LOGGER.error(
                    "[%s/%s] Error al escanear %s: %s",
                    indice, len(repositorios), repo_path, error,
                )

        LOGGER.info(
            "Resumen final | total_repos=%s | repos_analizados=%s | "
            "archivos_generados=%s | errores=%s",
            len(repositorios), contadores["analizados"], contadores["archivos"],
            contadores["errores"],
        )

    def run_grype(self, repo_path: str) -> str:
        """Ejecuta Grype en el repositorio y devuelve JSON con vulnerabilidades."""
        ruta_repo = self.project_root / repo_path
        self._validar_repositorio(ruta_repo)

        manifests = self._detectar_manifests(ruta_repo)
        if not manifests:
            LOGGER.warning(
                "No se encontraron manifests de dependencias en %s. Se omite.",
                ruta_repo.name,
            )
            return json.dumps({"matches": [], "source": None})

        LOGGER.info(
            "Manifests encontrados en %s: %s",
            ruta_repo.name, ", ".join(manifests),
        )

        grype_path = self.grype_path or self._resolver_grype()
        comando = [grype_path, str(
            ruta_repo), f"--output={FORMATO_SALIDA_GRYPE}"]

        LOGGER.info("Ejecutando Grype en %s...", ruta_repo.name)
        resultado = subprocess.run(
            comando, capture_output=True, text=True, check=False)

        try:
            if resultado.returncode != 0 and "error" in resultado.stderr.lower():
                raise RuntimeError(
                    f"Grype falló para {ruta_repo.name}: {resultado.stderr}"
                )
            LOGGER.debug("Grype stderr: %s", resultado.stderr)

            if not resultado.stdout:
                raise RuntimeError(
                    f"Grype no produjo salida para {ruta_repo.name}")

            return resultado.stdout
        finally:
            self._limpiar_archivos_generados()

    def _detectar_manifests(self, ruta_repo: Path) -> list[str]:
        """Detecta manifests de dependencias soportados por Grype."""
        manifests_encontrados = []
        generados = omitidos = 0
        for archivo in ruta_repo.rglob("*"):
            if not archivo.is_file():
                continue
            if archivo.name in MANIFESTS_SOPORTADOS:
                manifests_encontrados.append(archivo.name)
            elif archivo.name.lower() == "pyproject.toml":
                ruta_requirements = archivo.parent / "requirements.txt"
                if ruta_requirements.exists():
                    generados += 1
                elif self._generar_requirements_temporal(
                        archivo, ruta_requirements):
                    manifests_encontrados.append("requirements.txt")
                    generados += 1
                    self._archivos_generados.append(ruta_requirements)
                else:
                    omitidos += 1
        if generados or omitidos:
            LOGGER.info(
                "pyproject.toml: %s requirements.txt generados, %s omitidos",
                generados, omitidos,
            )
        return sorted(set(manifests_encontrados))

    def _generar_requirements_temporal(
            self, archivo: Path, ruta_requirements: Path) -> bool:
        """Genera requirements.txt temporal desde pyproject.toml para Grype."""
        resultado = subprocess.run(
            ["pip-compile", "--strip-extras",
                "pyproject.toml", "-o", ruta_requirements.name],
            cwd=archivo.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        if resultado.returncode == 0:
            return True
        salida = (resultado.stderr.strip() or resultado.stdout.strip())
        resumen = salida.splitlines()[-1][:300] if salida else "sin detalles"
        LOGGER.warning(
            "No se pudo generar requirements.txt desde %s. Se omite: %s",
            archivo.relative_to(self.project_root), resumen,
        )
        return False

    def _limpiar_archivos_generados(self):
        """Elimina los requirements.txt temporales generados en este análisis."""
        for ruta in self._archivos_generados:
            try:
                ruta.unlink(missing_ok=True)
            except OSError:
                LOGGER.debug("No se pudo eliminar el temporal %s", ruta)
        self._archivos_generados = []

    def parse_grype_output(self, grype_json_str: str) -> dict:
        """Convierte JSON de Grype a un formato normalizado."""
        try:
            grype_data = json.loads(grype_json_str)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"No se pudo analizar la salida JSON de Grype: {error}")

        contadores = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vulnerabilidades = []

        for vuln in grype_data.get("matches", []):
            vuln_norm = self._procesar_vulnerabilidad_grype(vuln)
            vulnerabilidades.append(vuln_norm)
            severidad = vuln_norm.get("vuln_severity", "low").lower()
            if severidad in contadores:
                contadores[severidad] += 1

        return {
            "total_vulnerabilities": len(vulnerabilidades),
            "vulnerabilities_by_severity": contadores,
            "vulnerabilities": vulnerabilidades,
            "grype_metadata": self._extraer_metadata(grype_data),
        }

    def _procesar_vulnerabilidad_grype(self, vuln: dict) -> dict:
        """Convierte un match de Grype a formato normalizado."""
        artifact = vuln.get("artifact", {})
        vulnerability = vuln.get("vulnerability", {})
        metadata = vuln.get("metadata", {})

        cvss_list = vulnerability.get("cvss")
        cvss_list = cvss_list if isinstance(cvss_list, list) else []
        cvss_score = cvss_list[0].get("metrics", {}).get(
            "baseScore", 0.0) if cvss_list else 0.0

        fix_versions = (vuln.get("fix") or {}).get("versions") or []

        return {
            "package_name": artifact.get("name", "unknown"),
            "current_version": artifact.get("version", "unknown"),
            "vuln_id": vulnerability.get("id", "unknown"),
            "vuln_severity": self._determinar_severidad_por_cvss(cvss_score),
            "fix_version": fix_versions[0] if fix_versions else "N/A",
            "message": vulnerability.get("description", ""),
            "cwe": metadata.get("cwe", "N/A"),
            "cvss_score": cvss_score,
            "type": vuln.get("type", "vulnerability"),
        }

    def _determinar_severidad_por_cvss(self, cvss_score: float) -> str:
        """Mapea CVSS score a nivel de severidad."""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    def _extraer_metadata(self, grype_data: dict) -> dict:
        """Extrae metadata de la salida de Grype."""
        fuente = grype_data.get("source") or {}
        return {
            "grype_version": grype_data.get("formatVersion", "unknown"),
            "db_location": fuente.get("dbPath", ""),
            "scanned_path": fuente.get("target", ""),
        }

    def save_analysis(
        self, repo_name: str, grype_raw: str, analysis_data: dict
    ) -> tuple[Path, Path]:
        """Guarda el análisis en dos formatos: raw (depuración) y normalizado."""
        if not repo_name:
            raise ValueError("El nombre del repositorio no puede estar vacío.")

        self.output_path.mkdir(parents=True, exist_ok=True)

        ruta_raw = self.output_path / f"{repo_name}{SUFIJO_GRYPE_RAW}"
        ruta_normalizado = self.output_path / f"{repo_name}{SUFIJO_GRYPE}"

        ruta_raw.write_text(grype_raw, encoding="utf-8")
        ruta_normalizado.write_text(
            json.dumps(analysis_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        LOGGER.info("Grype raw guardado en %s",
                    ruta_raw.relative_to(self.project_root))
        LOGGER.info(
            "Análisis Grype normalizado guardado en %s (total=%s)",
            ruta_normalizado.relative_to(self.project_root),
            analysis_data.get("total_vulnerabilities"),
        )
        return ruta_raw, ruta_normalizado

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

    def _resolver_grype(self) -> str:
        """Busca el ejecutable de Grype en PATH."""
        ruta_grype = shutil.which(self.grype_bin)
        if not ruta_grype:
            raise RuntimeError(MENSAJE_GRYPE_NO_INSTALADO)
        self.grype_path = ruta_grype
        return ruta_grype

    def _diagnosticar_entorno(self):
        """Verifica que Grype y su DB estén disponibles."""
        LOGGER.info("=== Diagnóstico del Entorno Grype ===")

        try:
            grype_path = self._resolver_grype()
            resultado = subprocess.run(
                [grype_path, "version"],
                capture_output=True, text=True, check=False,
            )
            LOGGER.info("✓ Grype CLI: %s", resultado.stdout.strip())
        except Exception as e:
            LOGGER.error("✗ Grype CLI: %s", e)

        try:
            resultado_db = subprocess.run(
                [self.grype_path, "db", "status"],
                capture_output=True, text=True, check=False,
            )
            LOGGER.info("✓ Grype DB: %s", resultado_db.stdout.strip())
        except Exception as e:
            LOGGER.warning(
                "⚠ Grype DB no disponible (se descargará en el primer uso): %s", e)

        LOGGER.info("=== Fin Diagnóstico ===\n")

    def _eliminar_archivos_parciales(self, repo_name: str):
        """Limpia archivos si falla el análisis."""
        for sufijo in [SUFIJO_GRYPE_RAW, SUFIJO_GRYPE]:
            ruta = self.output_path / f"{repo_name}{sufijo}"
            if ruta.exists():
                ruta.unlink()


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Genera análisis de vulnerabilidades con Grype en JSON "
                    "para todos los repositorios."
    )
    parser.add_argument(
        "--repos-path",
        default=str(RUTA_REPOS_POR_DEFECTO),
        help="Ruta al directorio que contiene los repositorios a escanear.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Ruta al directorio donde se guardarán los análisis Grype.",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Ejecuta un diagnóstico del entorno sin escanear repositorios.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    analizador = GrypeAnalyzer(args.repos_path, args.output_path)

    try:
        if args.diagnose:
            analizador._diagnosticar_entorno()
        else:
            analizador.run()
    except Exception as error:
        LOGGER.error(f"Error fatal: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
