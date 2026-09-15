from pathlib import Path
from generate_github_api import GetReposGitHubAPI
from generate_sboms import SBOMGenerator
from generate_codeql import CodeQLAnalyzer
from generate_grype import GrypeAnalyzer


def main():
    RUTA_BASE = Path(__file__).resolve().parents[1]
    RUTA_REPOS = RUTA_BASE / "miner" / "repos"
    RUTA_RESULTADOS = RUTA_BASE / "results"

    # Paso 1: Obtener y clonar repositorios de GitHub
    github_org = "vercel"
    cantidad_repos = 25
    github_api = GetReposGitHubAPI(str(RUTA_REPOS), github_org)
    github_api.run(cantidad_repos)

    # Paso 2: Generar SBOMs con Syft
    sbom_generator = SBOMGenerator(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    sbom_generator.run()

    # Paso 3: Analizar con CodeQL
    codeql_analyzer = CodeQLAnalyzer(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    codeql_analyzer.run()
    codeql_analyzer.run_cicd_analysis()

    # Paso 4: Analizar con Grype
    grype_analyzer = GrypeAnalyzer(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    grype_analyzer.run()


if __name__ == "__main__":
    main()
