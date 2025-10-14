# gateway

to run all the microservices 

docker-compose up --build

#run docker compose for other env
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

#Run docker compose for local
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d

