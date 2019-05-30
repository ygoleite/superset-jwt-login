from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from .security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
from superset import config 
import sqlalchemy as db
import psycopg2
import ast
import os
import base64

def tokenDigest (token, b64redir):

    conn_url = config.JWT_CONNECTION_STRING.format(config.JWT_DB_USER, config.JWT_DB_PASS, config.JWT_HOST, config.JWT_PORT, config.JWT_DB)
    engine = db.create_engine(conn_url)
    connection = engine.connect()
    metadata = db.MetaData()

    jwt_table = db.Table(config.JWT_TABLE, metadata, autoload=True, autoload_with=engine)

    queryDB = db.select([jwt_table]).where(jwt_table.columns.token == token)

    data = connection.execute(queryDB).fetchall()

    print(data)

    # Query Result Digest
    userInfo={}
    userInfo['user']=data[0][0]
    userInfo['redirect']=str(base64.urlsafe_b64decode(data[0][2]), 'utf-8')

    return userInfo

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'    

    @expose('/login/sso', methods=['GET', 'POST'])
    def login(self):   

        redirect_url = self.appbuilder.get_url_for_index

        token = request.args.get('token')
        b64redir = request.args.get('redirect')        

        if b64redir is not None and token is not None:
            authDict = tokenDigest(token, request.args.get('redirect'))
            user = self.appbuilder.sm.find_user(username=authDict['user'])
            if user is not None:
                login_user(user, remember=False)
                return redirect(authDict['redirect'])
            else:
                flash('Wrong user or user not found!', 'warning')
                return super(CustomAuthDBView,self).login()
        elif g.user is not None and g.user.is_authenticated():
            return redirect(redirect_url)
        else:
            flash('Unable to auto login - no token found!', 'warning')
            return super(CustomAuthDBView,self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)