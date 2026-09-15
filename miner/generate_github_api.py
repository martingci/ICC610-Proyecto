"""
Obtención de datos de GitHub a través de su API. 

Script que automatiza la obtención de repositorios de Github,
por medio de uso de su API pública y generación de clones. 

Proceso: 
1. Obtiene los repositorios desde GitHub a través de su API pública.
2. Filtra en base a los lenguajes de programación soportados.
3. Checkea que el repositorio no haya sido procesado previamente.
4. Clona el repositorio localmente para su posterior análisis.


Uso:
    - Se debe de importar el objeto y especificar la ruta y la organización de GitHub a análizar.

Salida: 
    - Se generan los clones de los repositorios en la ruta especificada, 
    listos para su análisis posterior.

"""

import json
import requests
import subprocess
from pathlib import Path


class GetReposGitHubAPI:
    def __init__(self, repos_path: str, github_org: str):
        self.repos_path = repos_path
        self.github_org = github_org
        self.supported_languages = ["Python", "JavaScript", "TypeScript"]

    def get_repos(self, page: int) -> list[str]:
        """Obtiene los repositorios de la organización de GitHub especificada."""
        url = (f"https://api.github.com/search/repositories?q=org:{self.github_org}"
               f"&sort:stars&order=desc"
               f"&per_page=30"
               f"&page={page}")
        response = requests.get(url)

        if response.status_code != 200:
            raise Exception(
                f"Error al obtener repositorios: {response.status_code}")
            return []

        return json.loads(response.text)["items"]

    def filter_repos_by_language(self, repos: list[dict]) -> list[dict]:
        """Filtra los repositorios por los lenguajes de programación soportados."""
        return [repo for repo in repos if repo["language"] in self.supported_languages]

    def get_useful_repos(self, quantity: int) -> list[dict]:
        """Obtiene los repositorios útiles para el análisis."""
        useful_repos = []
        page = 1

        while len(useful_repos) < quantity:
            repos = self.get_repos(page)
            filtered_repos = self.filter_repos_by_language(repos)
            for repo in filtered_repos:
                useful_repos.append(repo)
            page += 1

        return useful_repos[:quantity]

    def clone_repo(self, repo_url: str, destination: Path) -> None:
        """Clona el repositorio en la ruta especificada."""
        subprocess.run(["git", "clone", repo_url,
                       str(destination)], check=True)

    def run(self, quantity: int) -> None:
        """Ejecuta el proceso de obtención y clonación de repositorios."""
        useful_repos = self.get_useful_repos(quantity)

        for repo in useful_repos:
            repo_name = repo["name"]
            repo_url = repo["clone_url"]
            destination = Path(self.repos_path) / repo_name

            if destination.exists():
                print(
                    f"El repositorio {repo_name} ya existe en {destination}. Saltando clonación.")
                continue
            print(
                f"Clonando el repositorio {repo_name} desde {repo_url} a {destination}...")
            self.clone_repo(repo_url, destination)
