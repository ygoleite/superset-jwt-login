from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from .security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
from superset import config 
import sqlalchemy as db
import base64

def isBase64(sb):
    try:
        if type(sb) == str:
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif type(sb) == bytes:
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")                
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False

def tokenDigest (token, b64redir):

    conn_url = config.JWT_CONNECTION_STRING.format(config.JWT_DB_USER, config.JWT_DB_PASS, config.JWT_HOST, config.JWT_PORT, config.JWT_DB)
    engine = db.create_engine(conn_url)
    connection = engine.connect()
    metadata = db.MetaData()

    jwt_table = db.Table(config.JWT_TABLE, metadata, autoload=True, autoload_with=engine)

    queryDB = db.select([jwt_table]).where(jwt_table.columns.token == token)

    data = connection.execute(queryDB).fetchall()

    # Query Response - Digest
    username = data[0][0]
    encodedURL = data[0][2]

    if len(data) > 0:
        userInfo={}
        userInfo['user']=username
        checkUrl64 = isBase64(b64redir)
        if checkUrl64:
            userInfo['redirect']=str(base64.urlsafe_b64decode(encodedURL), 'utf-8')
        else:
            userInfo['redirect']=b64redir
        
        return userInfo
    else: 
        return {}

class CustomJWTAuthView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'    

    @expose('/login/sso', methods=['GET', 'POST'])
    def login(self):   

        redirect_url = self.appbuilder.get_url_for_index
        #Get Params
        token = request.args.get('token')
        b64redir = request.args.get('redirect')
        
        # Check authentication for older versions
        if "0.28." in str(config.VERSION_STRING):
            authenticated = g.user.is_authenticated
        else:
            authenticated = g.user.is_authenticated()

        if b64redir is None:
            b64redir = b'/superset/welcome'

        # Login in first time
        if b64redir is not None and token is not None:
            authDict = tokenDigest(token, b64redir)
            if 'user' in authDict:
                user = self.appbuilder.sm.find_user(username=authDict['user'])
                if user is not None:
                    login_user(user, remember=False)
                    return redirect(authDict['redirect'])
                else:
                    flash('Wrong user or user not found!', 'warning')
                    return super(CustomJWTAuthView,self).login()
            else:
                flash('Invalid Token', 'warning')
                return super(CustomJWTAuthView,self).login()
        
        # User already loged in case
        
        elif g.user is not None and authenticated:
            return redirect(redirect_url)
        # Token not found or not passed as a param
        else:
            flash('Unable to auto login - no token found!', 'warning')
            return super(CustomJWTAuthView,self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomJWTAuthView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)