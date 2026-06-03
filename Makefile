.PHONY: up down logs api-shell fmt test seed compile

up:            ## Bring up the full dev stack
	docker compose up --build

down:          ## Tear down the dev stack
	docker compose down

logs:          ## Tail API + worker logs
	docker compose logs -f api worker

api-shell:     ## Shell into the API container
	docker compose exec api bash

compile:       ## Syntax-check all backend Python (no deps needed)
	cd backend && python -m compileall -q app

test:          ## Run backend tests
	cd backend && pytest -q

fmt:           ## Format backend
	cd backend && ruff check --fix . && ruff format .
