from flask import Flask, jsonify, request, Blueprint
from flask_cors import CORS
from waitress import serve
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, verify_jwt_in_request
import json
import datetime
import re
import requests


app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "LlaveSecreta"
jwt = JWTManager(app)

def infoJSON():
    with open('config.json') as file:
        data = json.load(file)
    return data


@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludeRoutes = ['/login']
    if excludeRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        user = get_jwt_identity()
        if user['rol'] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, user['rol']['_id'])
            if not tienePermiso:
                return jsonify({"Mensaje": "Permiso, denegado"}), 401
        else:
            return jsonify({"Mensaje": "Permiso, denegado"}), 401

def limpiarURL(url):
    partes = request.path.split("/")
    for parte in partes:
        if re.search('\\d', parte):
            url = url.replace(parte, "?")
    return url

def validarPermiso(endPoint, metodo, idRol):
    url= infoJSON()['url_security']+"/permisos-rol/validar/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso



@app.post("/login")
def create_token():
    data = request.get_json()
    header = {"Content-Type": "application/json; charset=utf-8"}
    url = infoJSON()["url_security"] + "/users/validacion"
    response = requests.post(url, json=data, headers=header)
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


@app.get("/")
def test():
    json={}
    json["Mensaje"] = "Bien"
    return jsonify(json)




if __name__ == '__main__':
    info = infoJSON()
    print("Corriendo en: " + "http://" + info['url']+ ":"+ str(info['port']))
    serve(app, host=info['url'], port=info['port'])




