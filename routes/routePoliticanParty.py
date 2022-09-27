from app import infoJSON
from flask import Blueprint, request, jsonify
import requests

pp = Blueprint('pp', __name__)

@pp.get("/pp")
def indexPP():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = infoJSON()['url_back']+ "/pp"
    response = requests.get(url=url, headers=headers)
    json = response.json()
    return jsonify(json)

