from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

app = Flask(__name__);
cors = CORS(app)

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que se conveniente
jwt = JWTManager(app)

@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)

@app.route("/login", methods=["POST"])    
def createToken():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"]+ "/users/login"
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200 :
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), response.status_code

@app.before_request
def beforeRequestCallback():
    endpoint =  cleanUrl(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        user = get_jwt_identity()
        if user["role"] is not None:
            permission = validatePermission(endpoint, request.method, user["role"]["_id"])
            if not permission:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401


def cleanUrl(url):
    partsUrl =  url.split("/")
    for  theUrl in partsUrl:
         if re.search("\\d", theUrl):
            url = url.replace(theUrl, "?")
    return url

def validatePermission(endpoint, method, id_role):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"]+ "/permissions-roles/validate-permission/role/" + str(id_role)
    permission = False
    body = {
        "url": endpoint,
        "method": method
    }

    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if("_id" in data):
            permission = True
    except:
        pass
    return permission


#-------------------methods Candidates -----------------------------------
@app.route("/candidates", methods=['GET'])
def getCandidates():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/candidates'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/candidates", methods=['POST'])
def createCandidate():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/candidates'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/candidates/<string:id>",methods=['GET'])
def getCandidate(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/candidates/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/candidates/<string:id>", methods=['PUT'])
def updateCandidate(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/candidates/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/candidates/<string:id>", methods=['DELETE'])
def deleteCandidate(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/candidates/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())
#------------------- end methods Candidates -------------------------------
    
#-------------------methods Political Parties -----------------------------
@app.route("/political-parties", methods=['GET'])
def getPoliticalParties():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/political-parties'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/political-parties", methods=['POST'])
def createPoliticalParty():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/political-parties'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/political-parties/<string:id>",methods=['GET'])
def getPoliticalParty(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/political-parties/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/political-parties/<string:id>", methods=['PUT'])
def updatePoliticalParty(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/political-parties/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/political-parties/<string:id>", methods=['DELETE'])
def deletePoliticalParty(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/political-parties/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())
#------------------- end methods Political Parties ------------------------

#-------------------methods Results -----------------------------
@app.route("/results", methods=['GET'])
def getResults():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/results'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/results", methods=['POST'])
def createResult():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/results'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/results/<string:id>",methods=['GET'])
def getResult(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/results/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/results/<string:id>", methods=['PUT'])
def updateResult(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/results/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/results/<string:id>", methods=['DELETE'])
def deleteResult(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/results/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())
#------------------- end methods Results ------------------------

#-------------------methods Voting tables -----------------------
@app.route("/voting-tables", methods=['GET'])
def getVotingTables():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/voting-tables'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/voting-tables", methods=['POST'])
def createVotingTable():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/voting-tables'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/voting-tables/<string:id>",methods=['GET'])
def getVontingTable(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/voting-tables/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/voting-tables/<string:id>", methods=['PUT'])
def updateVotingTable(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/voting-tables/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/voting-tables/<string:id>", methods=['DELETE'])
def deleteVotingTable(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/voting-tables/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())
#------------------- end methods Voting tables -------------------

#-------------------methods reporsts -----------------------

@app.route("/vote-list/<string:id_table>", methods=['GET'])
@app.route("/vote-list", methods=['GET'])
def voteList(id_table=None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if id_table != None:
        url = dataConfig["url_backend_results"] + '/vote-list/'+id_table
    else:
        url = dataConfig["url_backend_results"] + '/vote-list'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())

@app.route("/get-votes-candidates/<string:id_table>", methods=['GET'])
@app.route("/get-votes-candidates", methods=['GET'])
def getVotesCandidates(id_table=None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if id_table != None:
        url = dataConfig["url_backend_results"] + '/get-votes-candidates/'+id_table
    else:
        url = dataConfig["url_backend_results"] + '/get-votes-candidates'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/total-votes-table", methods=['GET'])
def totalVotesTable():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/total-votes-table'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())

@app.route("/total-votes-political-party/<string:id_table>", methods=['GET'])
@app.route("/total-votes-political-party", methods=['GET'])
def totalVotesPoliticalParty(id_table=None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if id_table != None:
        url = dataConfig["url_backend_results"] + '/total-votes-political-party/'+id_table
    else:
        url = dataConfig["url_backend_results"] + '/total-votes-political-party'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/percentage-congress", methods=['GET'])
def percentageCongress():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_results"] + '/percentage-congress'
    response = requests.get(url, headers=headers)
    return jsonify(response.json()) 

#------------------- end reporsts -------------------

#-------------------methods permissions -----------------------
@app.route("/permissions", methods=['GET'])
def getPermissions():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/permissions", methods=['POST'])
def createPermission():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/permissions/<string:id>",methods=['GET'])
def getPermission(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/permissions/<string:id>", methods=['PUT'])
def updatePermission(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/permissions/<string:id>", methods=['DELETE'])
def deletePermission(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(None), response.status_code

#------------------- end methods permissions -------------------

#-------------------methods permissions and roles -----------------------
@app.route("/permissions-roles", methods=['GET'])
def getPermissionsRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions-roles'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/permissions-roles/permission/<string:id_permission>/role/<string:id_role>", methods=['POST'])
def createPermissionRole(id_permission, id_role):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions-roles/permission/'+ id_permission + '/role/' + id_role
    response = requests.post(url, headers=headers)
    return jsonify(response.json())
@app.route("/permissions-roles/<string:id>",methods=['GET'])
def getPermissionRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions-roles/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/permissions-roles/<string:id>/permission/<string:id_permission>/role/<string:id_role>", methods=['PUT'])
def updatePermissionRole(id, id_permission, id_role):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions-roles/' + id + '/permission/'+ id_permission + '/role/' + id_role
    response = requests.put(url, headers=headers)
    return jsonify(response.json())
@app.route("/permissions-roles/<string:id>", methods=['DELETE'])
def deletePermissionRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions-roles/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(None), response.status_code
@app.route("/permissions-roles/validate-permission/role/<string:id_role>",methods=['GET'])
def validatePermissionRole(id_role):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/permissions-roles/validate-permission/role/'+id_role
    response = requests.get(url, headers=headers, json=data)
    return jsonify(response.json())
#------------------- end methods permissions and roles -------------------

#-------------------methods roles -----------------------
@app.route("/roles", methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/roles'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/roles", methods=['POST'])
def createRole():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/roles'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/roles/<string:id>",methods=['GET'])
def getRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/roles/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/roles/<string:id>", methods=['PUT'])
def updateRole(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/roles/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/roles/<string:id>", methods=['DELETE'])
def deleteRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/roles/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(None), response.status_code
#------------------- end methods roles -------------------

#-------------------methods roles -----------------------
@app.route("/users", methods=['GET'])
def getUsers():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/users'
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/users", methods=['POST'])
def createUser():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/users'
    response = requests.post(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/users/<string:id>",methods=['GET'])
def getUser(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/users/'+id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())
@app.route("/users/<string:id>", methods=['PUT'])
def updateUser(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/users/'+id
    response = requests.put(url, headers=headers, json=data)
    return jsonify(response.json())
@app.route("/users/<string:id>", methods=['DELETE'])
def deleteUser(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/users/'+id
    response = requests.delete(url, headers=headers)
    return jsonify(None), response.status_code
@app.route("/users/assign-role/<string:id>/role/<string:id_role>", methods=['PUT'])
def assignRoleUser(id, id_role):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url_backend_security"] + '/users/assign-role/'+id+ '/role/'+ id_role 
    response = requests.put(url, headers=headers)
    return jsonify(response.json())

#------------------- end methods roles -------------------

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])