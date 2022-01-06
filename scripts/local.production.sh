#!/bin/bash

export COMPOSE_IGNORE_ORPHANS=True

# db migration
export DB_MIGRATION_IMAGE=learn-go-restful-api-db-migration
export DB_MIGRATION_IMAGE_TAG=production
export DB_MIGRATION_CONTAINER=learn-go-restful-api-db-migration-production
export DB_MIGRATION_HOST=learn-go-restful-api-db-migration.service
export BACKEND_STAGE=production

docker build -t "$DB_MIGRATION_IMAGE:$DB_MIGRATION_IMAGE_TAG" .
docker-compose -f ./manifest/docker-compose.production.yaml up -d --build
