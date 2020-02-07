# Flask FirecREST demo

This is a simple Flask-based web app to demonstrate the FirecRest web api.
In order to build the container image, `cd` inside the directory and then execute:

 `docker build -t <my_image_name> .`

In case of problems during the pip installation phase, add option `--network=host` for the docker build.

You can then run with:

`docker run -d -p 5000:5000 --rm --name <my_container_came> <my_image_name>`.

The above command is going to start the container in **detached mode** and remove it when it exits.

In order for the web app to work correctly a `client_secrets.json` file is needed filled with the necessary info.

The **SECRET_KEY** has to be defined in the `config.py`.
Furthermore, the **FIRECREST_IP** variable has to be defined in `config.py`.
This is the ip (including the port number) of the FirecREST api.
Additionally, the **MACHINES** which is the list of strings with the supported machine names has to be defined in `config.py` along with their **PARTITIONS**.
**HOME_DIR** should be specified.

