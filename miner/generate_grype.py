"""
Análisis de Vulnerabilidades con Grype

Script que automatiza el escaneo de vulnerabilidades en dependencias sobre múltiples
repositorios usando Grype, una herramienta de análisis de seguridad enfocada en
Software Component Analysis (SCA).

Proceso:
1. Descubre todos los repositorios en data/repos/
2. Escanea cada repositorio buscando manifests de dependencias
3. Ejecuta Grype para detectar vulnerabilidades conocidas
4. Normaliza la salida JSON de Grype
5. Guarda resultados en data/results/ con dos formatos:
   - {repo-name}-grype-raw.json: Salida original de Grype (para debug)
   - {repo-name}-grype.json: Formato normalizado (para análisis)

Uso:
    python scripts/generate_grype.py                    # Ejecutar análisis completo
    python scripts/generate_grype.py --dry-run          # Ver qué se haría sin ejecutar
    python scripts/generate_grype.py --repos-path PATH  # Con rutas personalizadas

Requisitos:
    - Grype CLI instalado (https://github.com/anchore/grype)
    - Grype DB actualizada (se descarga automáticamente en primer uso)
    - Repositorios clonados en data/repos/

Salida:
    - Archivos JSON en data/results/ con patrones:
      * {repo-name}-grype-raw.json: Salida original de Grype
      * {repo-name}-grype.json: Formato normalizado
    - Logs con progreso e información de errores
    - Resumen final con estadísticas de vulnerabilidades
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from pathlib import Path


RUTA_BASE_GRYPE = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE_GRYPE / "data" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE_GRYPE / "data" / "results"
SUFIJO_GRYPE_RAW = "-grype-raw.json"
SUFIJO_GRYPE = "-grype.json"
FORMATO_SALIDA_GRYPE = "json"
MENSAJE_GRYPE_NO_INSTALADO = (
    "Grype CLI is not installed. Please install it from "
    "https://github.com/anchore/grype"
)


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
        self.dry_run = False
        self.grype_path: str | None = None

    def discover_repositories(self) -> list[str]:
        """Devuelve una lista de rutas de repositorios."""
        self._validar_directorio_repos()

        repositorios = sorted(
            str(ruta.relative_to(self.project_root))
            for ruta in self.repos_path.iterdir()
            if ruta.is_dir()
        )

        if not repositorios:
            LOGGER.warning(f"No repositories found in {self.repos_path}")

        return repositorios

    def run_grype(self, repo_path: str) -> str:
        """Ejecuta Grype en el repositorio y devuelve JSON con vulnerabilidades."""
        ruta_repo = self.project_root / repo_path

        if not ruta_repo.exists():
            raise FileNotFoundError(
                f"Repository path does not exist: {ruta_repo}")

        if not ruta_repo.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {ruta_repo}")

        if not any(ruta_repo.iterdir()):
            raise ValueError(f"Repository directory is empty: {ruta_repo}")

        # Verificar que hay manifests que Grype puede procesar
        manifests = self._detectar_manifests(ruta_repo)
        if not manifests:
            LOGGER.warning(
                f"No dependency manifests found in {ruta_repo.name}. Skipping."
            )
            return json.dumps({"matches": [], "source": None})

        LOGGER.info(
            f"Manifests found in {ruta_repo.name}: {', '.join(manifests)}")

        # Ejecutar Grype
        grype_path = self.grype_path or self._resolver_grype()
        comando = [
            grype_path,
            str(ruta_repo),
            f"--output={FORMATO_SALIDA_GRYPE}",
        ]

        LOGGER.info(f"Running Grype on {ruta_repo.name}...")
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=False,
        )

        if resultado.returncode != 0:
            # Grype retorna 0 si no hay vulnerabilidades, pero puede retornar >0 en otros casos
            # Solo falla si hay error real (no simplemente "no vulnerabilidades")
            if "error" in resultado.stderr.lower():
                raise RuntimeError(
                    f"Grype analysis failed for {ruta_repo.name}: {resultado.stderr}"
                )
            # Si solo es warning/info, continuar
            LOGGER.debug(f"Grype stderr: {resultado.stderr}")

        if not resultado.stdout:
            raise RuntimeError(
                f"Grype produced no output for {ruta_repo.name}")

        return resultado.stdout

    def parse_grype_output(self, grype_json_str: str) -> dict:
        """Convierte JSON de Grype a un formato normalizado."""
        LOGGER.info("Parsing Grype output...")

        try:
            grype_data = json.loads(grype_json_str)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Failed to parse Grype JSON output: {error}")

        # Extraer vulnerabilidades
        vulnerabilidades_raw = grype_data.get("matches", [])
        LOGGER.info(
            f"Found {len(vulnerabilidades_raw)} matches in Grype output")

        # Normalizar
        resultados = {
            "total_vulnerabilities": len(vulnerabilidades_raw),
            "vulnerabilities_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "vulnerabilities": [],
            "grype_metadata": self._extraer_metadata(grype_data),
        }

        for vuln in vulnerabilidades_raw:
            vuln_norm = self._procesar_vulnerabilidad_grype(vuln)
            resultados["vulnerabilities"].append(vuln_norm)

            severity = vuln_norm.get("vuln_severity", "low").lower()
            if severity in resultados["vulnerabilities_by_severity"]:
                resultados["vulnerabilities_by_severity"][severity] += 1

        LOGGER.info(
            f"Parsed {resultados['total_vulnerabilities']} vulnerabilities total"
        )
        return resultados

    def save_analysis(self, repo_name: str, grype_raw: str, analysis_data: dict) -> tuple[Path, Path]:
        """Guarda el análisis en dos formatos: raw (debug) y normalizado (análisis)."""
        if not repo_name:
            raise ValueError("Repository name cannot be empty.")

        self.output_path.mkdir(parents=True, exist_ok=True)

        # Guardar formato raw (original de Grype)
        ruta_raw = self.output_path / f"{repo_name}{SUFIJO_GRYPE_RAW}"
        ruta_raw.write_text(grype_raw, encoding="utf-8")
        LOGGER.info(
            f"Raw Grype output saved to {ruta_raw.relative_to(self.project_root)}"
        )

        # Guardar formato normalizado
        ruta_normalizado = self.output_path / f"{repo_name}{SUFIJO_GRYPE}"
        contenido_json = json.dumps(
            analysis_data, ensure_ascii=False, indent=2)
        ruta_normalizado.write_text(contenido_json, encoding="utf-8")
        LOGGER.info(
            f"Normalized analysis saved to {ruta_normalizado.relative_to(self.project_root)}"
        )

        return ruta_raw, ruta_normalizado

    def run(self):
        """Orquesta el descubrimiento y análisis con Grype."""
        repositorios = self.discover_repositories()
        self._validar_directorio_salida()

        if not repositorios:
            LOGGER.warning("No repositories discovered. Exiting.")
            return

        if not self.dry_run:
            self._diagnosticar_entorno()

        self.output_path.mkdir(parents=True, exist_ok=True)

        repositorios_analizados = 0
        archivos_generados = 0
        omitidos = 0
        errores = 0

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path

            try:
                if self.dry_run:
                    LOGGER.info(
                        f"[{indice}/{len(repositorios)}] Dry-run: would scan {repo_path}"
                    )
                    omitidos += 1
                    continue

                LOGGER.info(
                    f"[{indice}/{len(repositorios)}] Scanning {repo_path} with Grype..."
                )

                # Ejecutar análisis
                grype_output = self.run_grype(repo_path)

                # Procesar resultados
                analysis = self.parse_grype_output(grype_output)

                # Guardar ambos formatos
                self.save_analysis(ruta_repo.name, grype_output, analysis)

                repositorios_analizados += 1
                archivos_generados += 2  # raw + normalizado

            except Exception as error:
                errores += 1
                self._eliminar_archivos_parciales(ruta_repo.name)
                LOGGER.error(f"Error scanning {repo_path}: {error}")

        LOGGER.info(
            (
                f"Summary | total_repos={len(repositorios)} | "
                f"repos_scanned={repositorios_analizados} | "
                f"files_generated={archivos_generados} | "
                f"skipped={omitidos} | errors={errores}"
            )
        )

    def _validar_directorio_repos(self):
        if not self.repos_path.exists():
            raise FileNotFoundError(
                f"Repos directory not found: {self.repos_path}")

        if not self.repos_path.is_dir():
            raise NotADirectoryError(
                f"Repos path is not a directory: {self.repos_path}")

    def _validar_directorio_salida(self):
        if self.output_path.exists() and not self.output_path.is_dir():
            raise NotADirectoryError(
                f"Output path exists but is not a directory: {self.output_path}")

    def _resolver_grype(self) -> str:
        """Busca el ejecutable de Grype en PATH."""
        ruta_grype = shutil.which(self.grype_bin)
        if not ruta_grype:
            raise RuntimeError(MENSAJE_GRYPE_NO_INSTALADO)

        self.grype_path = ruta_grype
        return ruta_grype

    def _diagnosticar_entorno(self):
        """Verifica que Grype y su DB estén disponibles."""
        LOGGER.info("=== Grype Environment Diagnostics ===")

        try:
            grype_path = self._resolver_grype()
            resultado = subprocess.run(
                [grype_path, "version"],
                capture_output=True,
                text=True,
                check=False,
            )
            LOGGER.info(f"Grype CLI: {resultado.stdout.strip()}")
        except Exception as e:
            LOGGER.error(f"Grype CLI check failed: {e}")

        # Verificar DB
        try:
            resultado_db = subprocess.run(
                [grype_path, "db", "status"],
                capture_output=True,
                text=True,
                check=False,
            )
            LOGGER.info(f"Grype DB status: {resultado_db.stdout.strip()}")
        except Exception as e:
            LOGGER.warning(
                f"Grype DB check failed (will be downloaded on first use): {e}")

        LOGGER.info("=== Environment Check Complete ===\n")

    def _detectar_manifests(self, ruta_repo: Path) -> list[str]:
        """Detecta manifests de dependencias soportados por Grype."""
        manifests_soportados = {
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

        manifests_encontrados = []
        for archivo in ruta_repo.rglob("*"):
            if archivo.is_file() and archivo.name in manifests_soportados:
                manifests_encontrados.append(archivo.name)
            elif archivo.is_file() and archivo.name.lower() == "pyproject.toml":
                try:
                    print(
                        "INFO | pyproject.toml detectado, generando requirements.txt temporal para Grype...")
                    subprocess.call(["pip-compile", "--strip-extras", archivo.name.lower(),
                                    "-o", "requirements.txt"], cwd=archivo.parent)
                    manifests_encontrados.append("requirements.txt")
                except Exception as e:
                    if e in "get_requires_for_build_wheel":
                        LOGGER.warning(
                            "No se pudo generar requirements.txt desde pyproject.toml (Sin dependencias). Se omitirá este archivo.")
                        LOGGER.error(f"Error detalle: {e}")

        # Devolver lista única ordenada
        return sorted(set(manifests_encontrados))

    def _procesar_vulnerabilidad_grype(self, vuln: dict) -> dict:
        """Convierte un match de Grype a formato normalizado."""
        # Extraer información del match de Grype
        artifact = vuln.get("artifact", {})
        vulnerability = vuln.get("vulnerability", {})
        metadata = vuln.get("metadata", {})

        # Determinar severidad (Grype usa CVSS score)
        cvss_list = vulnerability.get("cvss", [])
        cvss_score = 0.0
        if cvss_list and isinstance(cvss_list, list) and len(cvss_list) > 0:
            cvss_score = cvss_list[0].get("metrics", {}).get("baseScore", 0.0)

        severity = self._determinar_severidad_por_cvss(cvss_score)

        return {
            "package_name": artifact.get("name", "unknown"),
            "current_version": artifact.get("version", "unknown"),
            "vuln_id": vulnerability.get("id", "unknown"),
            "vuln_severity": severity,
            "fix_version": vuln.get("fix", {}).get("versions", ["N/A"])[0] if vuln.get("fix") else "N/A",
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
        descriptor = grype_data.get("descriptor", {})
        return {
            "grype_version": grype_data.get("formatVersion", "unknown"),
            "db_location": grype_data.get("source", {}).get("dbPath", ""),
            "scanned_path": grype_data.get("source", {}).get("target", ""),
        }

    def _eliminar_archivos_parciales(self, repo_name: str):
        """Limpia archivos si falla el análisis."""
        for sufijo in [SUFIJO_GRYPE_RAW, SUFIJO_GRYPE]:
            ruta = self.output_path / f"{repo_name}{sufijo}"
            if ruta.exists():
                ruta.unlink()


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Genera análisis de vulnerabilidades con Grype en JSON para todos los repositorios."
    )
    parser.add_argument(
        "--repos-path",
        default=str(RUTA_REPOS_POR_DEFECTO),
        help="Path to directory containing repositories to scan.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Path to directory where Grype analyses will be saved.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show which repositories would be scanned without running Grype.",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Run environment diagnostics without scanning repositories.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    analizador = GrypeAnalyzer(args.repos_path, args.output_path)
    analizador.dry_run = args.dry_run

    try:
        if args.diagnose:
            analizador._diagnosticar_entorno()
        else:
            analizador.run()
    except Exception as error:
        LOGGER.error(f"Fatal error: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
