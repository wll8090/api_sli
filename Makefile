imagem = imagem_api_sli
api= conteiner_api_sli
rede= rede_api_sli

help:
		@echo "criar_image, del_image, criar_volume, run, stop"

criar_image:
		make stop
		docker build -t $(imagem) .

network:
		docker network create $(rede)

del_image:
		make stop
		docker image rm -f $(imagem)

run:
		docker run -d --network $(rede) --name $(api) -v ./:/main/ $(imagem)
		docker logs $(api)

i-run:
		docker run -it --name $(api) -v ./:/main/ $(imagem) bash

stop:
		docker rm -f $(api)

log:
		docker logs $(api)

update:
		make stop
		git pull
