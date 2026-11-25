"""Where the portal keeps its state.

One module so nothing has to guess, and so the database layer and the settings
layer can share the location without importing each other.

    data/portal.db          projects, regions, clusters, connections, accounts,
                            the audit trail and the server inventory
    data/repos/<pid>/<rgid> git working copies, one per region
    data/secrets/<pid>/     kubeconfigs, sealing certs, deploy keys — 0700

Only the database and the secrets directory hold anything sensitive, and both
are created with restrictive permissions below.
"""
import os

from .env import BASE, DATA_DIR

# where state lives, decided by the deployment (PORTAL_DATA_DIR) so a container
# can mount a volume for it
DATA = DATA_DIR
REPOS = DATA / "repos"
SECRETS = DATA / "secrets"

for _d in (DATA, REPOS, SECRETS):
    _d.mkdir(parents=True, exist_ok=True)
os.chmod(SECRETS, 0o700)
