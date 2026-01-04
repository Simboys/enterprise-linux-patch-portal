.PHONY: help build up down logs clean backup restore

help:
	@echo "Enterprise Linux Patch Portal - Make Commands"
	@echo ""
	@echo "  make build    - Build all Docker images"
	@echo "  make up       - Start all services"
	@echo "  make down     - Stop all services"
	@echo "  make logs     - View logs"
	@echo "  make clean    - Remove all containers and volumes"
	@echo "  make backup   - Backup database"
	@echo "  make restore  - Restore database from backup"
	@echo "  make shell    - Open backend shell"

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Portal is starting..."
	@echo "Frontend: http://localhost:3000"
	@echo "Backend API: http://localhost:5000"
	@echo "Nginx: http://localhost"

down:
	docker-compose down

logs:
	docker-compose logs -f

clean:
	docker-compose down -v
	@echo "All containers and volumes removed"

backup:
	@echo "Creating database backup..."
	docker-compose exec db pg_dump -U patchuser patchportal > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup completed"

restore:
	@read -p "Enter backup file name: " backup; \
	docker-compose exec -T db psql -U patchuser patchportal < $$backup

shell:
	docker-compose exec backend /bin/bash

test:
	@echo "Running tests..."
	docker-compose exec backend python -m pytest

init:
	@echo "Initializing project..."
	cp .env.example .env
	@echo "Please edit .env file with your configuration"
