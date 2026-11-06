# auth-api

API d'authentification FastAPI (register, login, route protégée /me) avec JWT et bcrypt.
Conteneurisée avec Docker, déployée via Azure DevOps.

## Chaîne de livraison
GitHub -> Azure Pipelines -> registre d'images -> Kubernetes

## Limites connues
- Utilisateurs stockés en mémoire (pas de base de données)
- Pas de limitation de tentatives de connexion
