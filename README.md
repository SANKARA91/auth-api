# auth-api

API d'authentification FastAPI (register, login, route protégée /me) avec JWT et bcrypt.
Conteneurisée avec Docker, déployée sur AKS via Azure DevOps.

## Chaîne de livraison
GitHub -> Azure Pipelines -> ACR -> AKS

## Limites connues
- Utilisateurs stockés en mémoire (pas de base de données)
- Pas de limitation de tentatives de connexion
