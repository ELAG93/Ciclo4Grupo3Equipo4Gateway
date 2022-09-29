from app import infoJSON, headers
from flask import Blueprint, request, jsonify
import requests


users = Blueprint('users', __name__)
info = infoJSON()

@users.get("/users")
def get_users():
    url_sec = info['url_security'] + "/users"
    response = requests.get(url_sec, headers)
    return jsonify(response.json())
