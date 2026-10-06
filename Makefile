.PHONY: up down logs api-shell fmt test compile clean

up:            ## Launch the full stack (first run builds images)
	docker compose up --build -d
	@echo ""
	@echo "  UI:       http://localhost:5173"
	@echo "  API docs: http://localhost:8000/docs"
	@echo "  MinIO:    http://localhost:9001  (hunter / hunter-secret)"
	@echo ""
	@echo "  Foundry is in MOCK mode. Set endpoint + key in Settings to go live."
	@echo ""
	@echo "  Logs:  make logs"
	@echo ""

up-attached:   ## Launch attached (see all logs)
	docker compose up --build

down:          ## Tear down
	docker compose down

clean:         ## Tear down + wipe volumes (DB, files, Redis)
	docker compose down -v

logs:          ## Tail API + worker logs
	docker compose logs -f api worker

api-shell:     ## Shell into the API container
	docker compose exec api bash

compile:       ## Syntax-check backend (no Docker needed)
	cd backend && python -m compileall -q app

test:          ## Run backend tests (no Docker needed)
	cd backend && python -m pytest -q

fmt:           ## Format backend
	cd backend && ruff check --fix . && ruff format .
