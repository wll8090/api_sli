
imagem = imagem_api_sli
api= conteiner_api_sli

help:
    @echo "criar_image, del_image, criar_volume, run, stop"

criar_image:
    make stop
    docker build -t $(imagem) .

del_image:
    docker image rm -f $(imagem)

run:
    docker run -p5001:5001 -d --name $(api) -v ./:/main/ $(imagem)

i-run:
    docker run -p5001:5001 -it --name $(api) -v ./:/main/ $(imagem) bash
stop:
    docker rm -f $(api)

logs:
    docker logs $(api)

update:
    make stop
    git pull