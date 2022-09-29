from flask import Flask, jsonify, request, Blueprint
from flask_cors import CORS
from waitress import serve
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, verify_jwt_in_request
import json
import datetime
import re
import requests
from routes.routePoliticanParty import pp


app = Flask(__name__)
cors = CORS(app)


app.register_blueprint(pp)





def infoJSON():
    with open('config.json') as file:
        data = json.load(file)
    return data


info = infoJSON()
headers = {"Content-Type": "application/json; charset=utf-8"}
denegado = {"mensaje": "Permiso denegado"}



app.config["JWT_SECRET_KEY"] = info['secret']
jwt = JWTManager(app)

def format_url():
    parts = request.path.split("/")
    url = request.path
    for part in parts:
        if re.search('\\d', part):
            url = url.replace(part, "?")
    return url



@app.before_request
def before_request_callback():
    request.path = format_url()
    excludeRoutes = ['/login', '/users', '/users/?/rol/?', '/']
    #Token
    if request.path not in excludeRoutes:
        if not verify_jwt_in_request():
            return jsonify(denegado), 401

        #Roles y permisos
        user = get_jwt_identity()
        if user['rol'] is None:
            return jsonify(denegado), 401
        else:
            rol_id = user['rol']['_id']
            route = format_url()
            method = request.method
            has_permission = validarPermiso(rol_id, route, method)
            if not has_permission:
                return jsonify(denegado), 401


def validarPermiso(idRol, endPoint, metodo):
    url= info['url_security']+"/permisos-rol/validar/rol/" + str(idRol)
    tienePermiso = False
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.post(url, json=body, headers=headers)
    try:
        data = response.json()
        if("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso


@app.get("/")
def test():
    return jsonify({"Mensaje": "Sí funcionó"})


@app.post("/login")
def create_token():
    data = request.get_json()
    url = info["url_security"] + "/users/validacion"
    response = requests.post(url, json=data, headers=headers)
    code = response.status_code

    if(code == 200):
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        response = response.text
        res = json.loads(response)
        return jsonify({'mensaje': res['mensaje']}), code






if __name__ == '__main__':
    print("Corriendo en: " + "http://" + info['url']+ ":"+ str(info['port']))
    serve(app, host=info['url'], port=info['port'])




