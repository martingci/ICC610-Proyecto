from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path


RUTA_BASE_SBOMS = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE_SBOMS / "data" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE_SBOMS / "data" / "results"
FORMATO_SALIDA_SYFT = "syft-json"
SUFIJO_SBOM = "-sbom.json"
SUFIJOS_LEGADOS = (".spdx.json", ".cyclonedx.json")
MENSAJE_SYFT_NO_INSTALADO = (
    "Syft CLI is not installed. Please install it (e.g., `brew install syft`)."
)


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)
PATRON_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class SBOMGenerator:
    def __init__(self, repos_path: str, output_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parents[1]
        self.syft_bin = "syft"
        self.dry_run = False
        self.syft_path: str | None = None

    def discover_repositories(self) -> list[str]:
        """Devuelve una lista de rutas de repositorios."""
        self._validar_directorio_repos()

        repositorios = sorted(
            str(ruta.relative_to(self.project_root))
            for ruta in self.repos_path.iterdir()
            if ruta.is_dir()
        )

        if not repositorios:
            LOGGER.warning("No se encontraron repositorios en %s", self.repos_path)

        return repositorios

    def generate_sbom(self, repo_path: str) -> str:
        """Ejecuta Syft y devuelve el SBOM JSON nativo."""
        ruta_repo = self.project_root / repo_path

        if not ruta_repo.exists():
            raise FileNotFoundError(f"El repositorio no existe: {ruta_repo}")

        if not ruta_repo.is_dir():
            raise NotADirectoryError(f"La ruta no es un directorio: {ruta_repo}")

        if not any(ruta_repo.iterdir()):
            raise ValueError(f"El repositorio esta vacio: {ruta_repo}")

        comando = self._construir_comando_syft(ruta_repo)
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=False,
        )

        if resultado.returncode != 0:
            detalle_error = resultado.stderr.strip() or "Syft termino con un error desconocido."
            raise RuntimeError(
                f"No fue posible generar el SBOM para {ruta_repo.name}: {detalle_error}"
            )

        salida = self._normalizar_sbom_json(resultado.stdout)
        if not salida.strip():
            raise RuntimeError(f"Syft no devolvio contenido para {ruta_repo.name}.")

        try:
            json.loads(salida)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Syft devolvio un JSON invalido para {ruta_repo.name}."
            ) from error

        return salida

    def save_sbom(self, repo_name: str, sbom_data: str) -> Path:
        """Guarda el SBOM en el directorio de salida."""
        if not repo_name:
            raise ValueError("El nombre del repositorio no puede estar vacio.")

        self.output_path.mkdir(parents=True, exist_ok=True)
        ruta_salida = self.output_path / f"{repo_name}{SUFIJO_SBOM}"
        ruta_salida.write_text(sbom_data, encoding="utf-8")
        LOGGER.info("SBOM guardado en %s", ruta_salida.relative_to(self.project_root))
        return ruta_salida

    def run(self):
        """Orquesta el descubrimiento y la generacion de SBOMs."""
        repositorios = self.discover_repositories()
        self._validar_directorio_salida()

        if not repositorios:
            return

        if not self.dry_run:
            self.syft_path = self._resolver_syft()
            LOGGER.info("Usando Syft CLI: %s", self.syft_path)

        self.output_path.mkdir(parents=True, exist_ok=True)

        repositorios_generados = 0
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

                ruta_salida = self.output_path / f"{ruta_repo.name}{SUFIJO_SBOM}"
                LOGGER.info(
                    "[%s/%s] Dry-run: se generaria %s",
                    indice,
                    len(repositorios),
                    ruta_salida.relative_to(self.project_root),
                )
                continue

            try:
                sbom_data = self.generate_sbom(repo_path)
                self.save_sbom(ruta_repo.name, sbom_data)
                self._eliminar_archivos_legados(ruta_repo.name)
                repositorios_generados += 1
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
            "Resumen final | total_repos=%s | repos_generados=%s | archivos_generados=%s | omitidos=%s | errores=%s",
            len(repositorios),
            repositorios_generados,
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

    def _resolver_syft(self) -> str:
        ruta_syft = shutil.which(self.syft_bin)
        if not ruta_syft:
            raise RuntimeError(MENSAJE_SYFT_NO_INSTALADO)

        return ruta_syft

    def _construir_comando_syft(self, ruta_repo: Path) -> list[str]:
        ruta_syft = self.syft_path or self._resolver_syft()
        return [ruta_syft, f"dir:{ruta_repo}", "-o", FORMATO_SALIDA_SYFT]

    def _normalizar_sbom_json(self, salida_cruda: str) -> str:
        """Limpia ruido accidental y reserializa el resultado como JSON valido."""
        if not salida_cruda or not salida_cruda.strip():
            return ""

        texto_limpio = PATRON_ANSI.sub("", salida_cruda).replace("\ufeff", "").strip()
        candidatos = [texto_limpio]

        inicio_objeto = texto_limpio.find("{")
        fin_objeto = texto_limpio.rfind("}")
        if inicio_objeto != -1 and fin_objeto != -1 and inicio_objeto < fin_objeto:
            candidatos.append(texto_limpio[inicio_objeto : fin_objeto + 1])

        inicio_lista = texto_limpio.find("[")
        fin_lista = texto_limpio.rfind("]")
        if inicio_lista != -1 and fin_lista != -1 and inicio_lista < fin_lista:
            candidatos.append(texto_limpio[inicio_lista : fin_lista + 1])

        for candidato in candidatos:
            try:
                contenido = json.loads(candidato)
            except json.JSONDecodeError:
                continue

            return json.dumps(contenido, ensure_ascii=False, indent=2)

        raise RuntimeError("Syft devolvio una salida que no pudo normalizarse a JSON valido.")

    def _eliminar_archivos_parciales(self, repo_name: str):
        ruta_salida = self.output_path / f"{repo_name}{SUFIJO_SBOM}"
        if ruta_salida.exists():
            ruta_salida.unlink()

    def _eliminar_archivos_legados(self, repo_name: str):
        for sufijo in SUFIJOS_LEGADOS:
            ruta_salida = self.output_path / f"{repo_name}{sufijo}"
            if ruta_salida.exists():
                ruta_salida.unlink()
                LOGGER.info("Archivo legado eliminado: %s", ruta_salida)


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Genera SBOMs en JSON para todos los repositorios usando Syft."
    )
    parser.add_argument(
        "--repos-path",
        default=str(RUTA_REPOS_POR_DEFECTO),
        help="Ruta al directorio que contiene los repositorios a analizar.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Ruta al directorio donde se guardaran los SBOMs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra que repositorios se procesarian sin ejecutar Syft.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    generador = SBOMGenerator(args.repos_path, args.output_path)
    generador.dry_run = args.dry_run
    try:
        generador.run()
    except Exception as error:
        LOGGER.error("%s", error)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())