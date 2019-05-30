from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from .security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
import psycopg2
import ast

def checkToken (token):
    return "{user : userName}"

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'    

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):   

        redirect_url = self.appbuilder.get_url_for_index
        if request.args.get('redirect') is not None:
            redirect_url = request.args.get('redirect') 

        if request.args.get('username') is not None:
            
            user = self.appbuilder.sm.find_user(username=request.args.get('username'))
            if user is not None:
                login_user(user, remember=False)
                return redirect(redirect_url)
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
